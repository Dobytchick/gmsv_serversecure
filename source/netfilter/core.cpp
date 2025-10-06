#include "core.hpp"
#include "baseserver.hpp"
#include "clientmanager.hpp"
#include <iostream>

#include <GarrysMod/FactoryLoader.hpp>
#include <GarrysMod/FunctionPointers.hpp>
#include <GarrysMod/InterfacePointers.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/Lua/LuaInterface.h>
#include <GarrysMod/Lua/Helpers.hpp>
#include <Platform.hpp>

#include <detouring/classproxy.hpp>
#include <detouring/hook.hpp>

#include <bitbuf.h>
#include <checksum_sha1.h>
#include <dbg.h>
#include <eiface.h>
#include <filesystem_stdio.h>
#include <game/server/iplayerinfo.h>
#include <iserver.h>
#include <steam/steam_gameserver.h>
#include <threadtools.h>
#include <utlvector.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <queue>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#if defined SYSTEM_WINDOWS

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SERVERSECURE_CALLING_CONVENTION __stdcall

#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <processthreadsapi.h>
#include <windows.h>

using ssize_t = int32_t;
using recvlen_t = int32_t;

#define PRIiSOCKET PRIuPTR
#define PRIiSSIZE PRIi32

#elif defined SYSTEM_POSIX

#define SERVERSECURE_CALLING_CONVENTION

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>

#if defined SYSTEM_LINUX

#include <sys/prctl.h>

#elif defined SYSTEM_MACOSX
// pthread already included above for POSIX
#endif

typedef int32_t SOCKET;
typedef size_t recvlen_t;

static const SOCKET INVALID_SOCKET = -1;

#define PRIiSOCKET PRIi32
#define PRIiSSIZE PRIiPTR

#endif

struct netsocket_t {
  int32_t nPort;
  bool bListening;
  int32_t hUDP;
  int32_t hTCP;
};

struct player_t {
  byte index;
  std::string name;
  double score;
  double time;
};

struct reply_player_t {
  bool dontsend = false;
  bool senddefault = true;

  byte count = 0;
  std::vector<player_t> players;
};

GarrysMod::Lua::ILuaBase *server_lua = nullptr;

// -------- main thread guard --------
#if defined(SYSTEM_WINDOWS)
static DWORD g_main_tid = 0;
static inline bool InMainThread() { return GetCurrentThreadId() == g_main_tid; }
#else
static pthread_t g_main_tid;
static inline bool InMainThread() { return pthread_equal(pthread_self(), g_main_tid); }
#endif

namespace netfilter {

// ---------- CBaseServerProxy: challenge helpers ----------

class CBaseServerProxy
    : public Detouring::ClassProxy<CBaseServer, CBaseServerProxy> {
private:
  using TargetClass = CBaseServer;
  using SubstituteClass = CBaseServerProxy;

public:
  explicit CBaseServerProxy(CBaseServer *baseserver) {
    Initialize(baseserver);
    Hook(&CBaseServer::CheckChallengeNr, &CBaseServerProxy::CheckChallengeNr);
    Hook(&CBaseServer::GetChallengeNr, &CBaseServerProxy::GetChallengeNr);
  }

  ~CBaseServerProxy() override {
    UnHook(&CBaseServer::CheckChallengeNr);
    UnHook(&CBaseServer::GetChallengeNr);
  }

  CBaseServerProxy(const CBaseServerProxy &) = delete;
  CBaseServerProxy(CBaseServerProxy &&) = delete;

  CBaseServerProxy &operator=(const CBaseServerProxy &) = delete;
  CBaseServerProxy &operator=(CBaseServerProxy &&) = delete;

  virtual bool CheckChallengeNr(const netadr_t &adr,
                                const int nChallengeValue) {
    if (adr.IsLoopback()) {
      return true;
    }

    if (IsX360()) {
      return true;
    }

    UpdateChallengeIfNeeded();

    m_challenge[4] = adr.GetIPNetworkByteOrder();

    CSHA1 hasher;
    hasher.Update(reinterpret_cast<uint8_t *>(&m_challenge[0]),
                  sizeof(uint32_t) * m_challenge.size());
    hasher.Final();
    SHADigest_t hash = {0};
    hasher.GetHash(hash);

    int hv = 0;
    std::memcpy(&hv, hash, sizeof(hv));
    if (hv == nChallengeValue) {
      return true;
    }

    // try previous
    m_previous_challenge[4] = adr.GetIPNetworkByteOrder();

    hasher.Reset();
    hasher.Update(reinterpret_cast<uint8_t *>(&m_previous_challenge[0]),
                  sizeof(uint32_t) * m_previous_challenge.size());
    hasher.Final();
    hasher.GetHash(hash);
    hv = 0;
    std::memcpy(&hv, hash, sizeof(hv));
    return hv == nChallengeValue;
  }

  virtual int GetChallengeNr(netadr_t &adr) {
    UpdateChallengeIfNeeded();

    m_challenge[4] = adr.GetIPNetworkByteOrder();

    CSHA1 hasher;
    hasher.Update(reinterpret_cast<uint8_t *>(&m_challenge[0]),
                  sizeof(uint32_t) * m_challenge.size());
    hasher.Final();
    SHADigest_t hash = {0};
    hasher.GetHash(hash);
    int hv = 0;
    std::memcpy(&hv, hash, sizeof(hv));
    return hv;
  }

  static void UpdateChallengeIfNeeded() {
    const double current_time = Plat_FloatTime();
    if (m_challenge_gen_time >= 0 &&
        current_time < m_challenge_gen_time + CHALLENGE_NONCE_LIFETIME) {
      return;
    }

    m_challenge_gen_time = current_time;
    m_previous_challenge.swap(m_challenge);

    m_challenge[0] = m_rng();
    m_challenge[1] = m_rng();
    m_challenge[2] = m_rng();
    m_challenge[3] = m_rng();
  }

  static std::mt19937 InitializeRNG() noexcept {
    try {
      return std::mt19937(std::random_device{}());
    } catch (const std::exception &e) {
      Warning("[ServerSecure] Failed to initialize RNG seed, fallback to time: %s\n", e.what());
      return std::mt19937(
          static_cast<uint32_t>(Plat_FloatTime() * 1000000));
    }
  }

  static std::mt19937 m_rng;
  static double m_challenge_gen_time;
  static std::array<uint32_t, 5> m_previous_challenge;
  static std::array<uint32_t, 5> m_challenge;

  static std::unique_ptr<CBaseServerProxy> Singleton;
};

std::mt19937 CBaseServerProxy::m_rng = CBaseServerProxy::InitializeRNG();
double CBaseServerProxy::m_challenge_gen_time = -1;
std::array<uint32_t, 5> CBaseServerProxy::m_previous_challenge;
std::array<uint32_t, 5> CBaseServerProxy::m_challenge;

std::unique_ptr<CBaseServerProxy> CBaseServerProxy::Singleton;

static bool CheckChallengeNr(const netadr_t &adr, const int nChallengeValue) {
  if (!CBaseServerProxy::Singleton) {
    return false;
  }
  return CBaseServerProxy::Singleton->CheckChallengeNr(adr, nChallengeValue);
}

// ------------------------- Core -------------------------

class Core {
private:
  struct server_tags_t {
    std::string gm;
    std::string gmws;
    std::string gmc;
    std::string loc;
    std::string ver;
  };

  struct reply_map_t {
    bool dontsend = false;     // вернуть false из хука — вообще не слать ответ
    bool senddefault = true;   // nil/true — отдать стандартный
    std::string map;           // строка — оверрайд карты
  };

  reply_player_t ch_players;

public:
  struct packet_t {
    packet_t() : address(), address_size(sizeof(address)) {}
    sockaddr_in address;
    socklen_t address_size;
    std::vector<uint8_t> buffer;
  };

  explicit Core(const char *game_version)
      : server(InterfacePointers::Server()) {

    if (server == nullptr) {
      throw std::runtime_error("failed to dereference IServer");
    }

    if (!server_loader.IsValid()) {
      throw std::runtime_error("unable to get server factory");
    }

    ICvar *icvar = InterfacePointers::Cvar();
    if (icvar != nullptr) {
      sv_visiblemaxplayers = icvar->FindVar("sv_visiblemaxplayers");
      sv_location = icvar->FindVar("sv_location");
    }

    if (sv_visiblemaxplayers == nullptr) {
      Warning("[ServerSecure] Failed to get \"sv_visiblemaxplayers\" convar!\n");
    }

    if (sv_location == nullptr) {
      Warning("[ServerSecure] Failed to get \"sv_location\" convar!\n");
    }

    gamedll = InterfacePointers::ServerGameDLL();
    if (gamedll == nullptr) {
      throw std::runtime_error("failed to load required IServerGameDLL interface");
    }

    engine_server = InterfacePointers::VEngineServer();
    if (engine_server == nullptr) {
      throw std::runtime_error("failed to load required IVEngineServer interface");
    }

    filesystem = InterfacePointers::FileSystem();
    if (filesystem == nullptr) {
      throw std::runtime_error("failed to initialize IFileSystem");
    }

    const FunctionPointers::GMOD_GetNetSocket_t GetNetSocket =
        FunctionPointers::GMOD_GetNetSocket();
    if (GetNetSocket != nullptr) {
      const netsocket_t *net_socket = GetNetSocket(1);
      if (net_socket != nullptr) {
        game_socket = net_socket->hUDP;
      }
    }

    if (game_socket == INVALID_SOCKET) {
      throw std::runtime_error("got an invalid server socket");
    }

    if (!recvfrom_hook.Enable()) {
      throw std::runtime_error("failed to detour recvfrom");
    }

    threaded_socket_execute = true;
    threaded_socket_handle = CreateSimpleThread(PacketReceiverThread, this);
    if (threaded_socket_handle == nullptr) {
      throw std::runtime_error("unable to create thread");
    }

    BuildStaticReplyInfo(game_version);
  }

  ~Core() {
    if (threaded_socket_handle != nullptr) {
      threaded_socket_execute = false;
      ThreadJoin(threaded_socket_handle);
      ReleaseThreadHandle(threaded_socket_handle);
      threaded_socket_handle = nullptr;
    }

    recvfrom_hook.Disable();
  }

  Core(const Core &) = delete;
  Core(Core &&) = delete;
  Core &operator=(const Core &) = delete;
  Core &operator=(Core &&) = delete;

  void BuildStaticReplyInfo(const char *game_version) {
    reply_info.game_desc = gamedll->GetGameDescription();

    {
      reply_info.game_dir.resize(256);
      engine_server->GetGameDir(
          &reply_info.game_dir[0],
          static_cast<int32_t>(reply_info.game_dir.size()));
      reply_info.game_dir.resize(std::strlen(reply_info.game_dir.c_str()));

      size_t pos = reply_info.game_dir.find_last_of("\\/");
      if (pos != std::string::npos) {
        reply_info.game_dir.erase(0, pos + 1);
      }
    }

    reply_info.max_clients = server->GetMaxClients();
    reply_info.udp_port = server->GetUDPPort();

    {
      const IGamemodeSystem::Information &gamemode =
          dynamic_cast<CFileSystem_Stdio *>(filesystem)->Gamemodes()->Active();

      if (!gamemode.name.empty()) {
        static const std::string_view suffix = "_modded";
        std::string_view gm_name = gamemode.name;
        if (gm_name.size() > suffix.size() &&
            gm_name.substr(gm_name.size() - suffix.size()) == suffix) {
          gm_name = gm_name.substr(0, gm_name.size() - suffix.size());
        }
        reply_info.tags.gm = gm_name;
      } else {
        reply_info.tags.gm.clear();
      }

      if (gamemode.workshopid != 0) {
        reply_info.tags.gmws = std::to_string(gamemode.workshopid);
      } else {
        reply_info.tags.gmws.clear();
      }

      if (!gamemode.category.empty()) {
        reply_info.tags.gmc = gamemode.category;
      } else {
        reply_info.tags.gmc.clear();
      }

      if (game_version != nullptr) {
        reply_info.tags.ver = game_version;
      }
    }

    {
      FileHandle_t file = filesystem->Open("steam.inf", "r", "GAME");
      if (file == nullptr) {
        reply_info.game_version = default_game_version;
        DevWarning("[ServerSecure] Error opening steam.inf\n");
        return;
      }

      std::array<char, 256> buff{};
      bool failed =
          filesystem->ReadLine(buff.data(), buff.size(), file) == nullptr;
      filesystem->Close(file);
      if (failed) {
        reply_info.game_version = default_game_version;
        DevWarning("[ServerSecure] Failed reading steam.inf\n");
        return;
      }

      reply_info.game_version = &buff[13];

      size_t pos = reply_info.game_version.find_first_of("\r\n");
      if (pos != std::string::npos) {
        reply_info.game_version.erase(pos);
      }
    }
  }

  static std::string ConcatenateTags(const server_tags_t &tags) {
    std::string strtags;

    if (!tags.gm.empty()) {
      strtags += "gm:";
      strtags += tags.gm;
    }

    if (!tags.gmws.empty()) {
      strtags += strtags.empty() ? "gmws:" : " gmws:";
      strtags += tags.gmws;
    }

    if (!tags.gmc.empty()) {
      strtags += strtags.empty() ? "gmc:" : " gmc:";
      strtags += tags.gmc;
    }

    if (!tags.loc.empty()) {
      strtags += strtags.empty() ? "loc:" : " loc:";
      strtags += tags.loc;
    }

    if (!tags.ver.empty()) {
      strtags += strtags.empty() ? "ver:" : " ver:";
      strtags += tags.ver;
    }

    return strtags;
  }

  void BuildReplyInfo() {
    const char *server_name = server->GetName();
    const char *map_name = server->GetMapName();
    const char *game_dir = reply_info.game_dir.c_str();
    const char *game_desc = reply_info.game_desc.c_str();
    const int32_t appid = engine_server->GetAppID();
    const int32_t num_clients = server->GetNumClients();

    int32_t max_players =
        sv_visiblemaxplayers != nullptr ? sv_visiblemaxplayers->GetInt() : -1;
    if (max_players <= 0 || max_players > reply_info.max_clients) {
      max_players = reply_info.max_clients;
    }

    const int32_t num_fake_clients = server->GetNumFakeClients();
    const bool has_password = server->GetPassword() != nullptr;

    if (gameserver == nullptr) {
      gameserver = SteamGameServer();
    }

    bool vac_secure = false;
    if (gameserver != nullptr) {
      vac_secure = gameserver->BSecure();
    }

    const char *game_version = reply_info.game_version.c_str();
    const int32_t udp_port = reply_info.udp_port;
    const CSteamID *sid = engine_server->GetGameServerSteamID();
    const uint64_t steamid = sid != nullptr ? sid->ConvertToUint64() : 0;

    if (sv_location != nullptr) {
      reply_info.tags.loc = sv_location->GetString();
    } else {
      reply_info.tags.loc.clear();
    }

    const std::string tags = ConcatenateTags(reply_info.tags);
    const bool has_tags = !tags.empty();

    info_cache_packet.Reset();

    info_cache_packet.WriteLong(-1);  // header
    info_cache_packet.WriteByte('I'); // type
    info_cache_packet.WriteByte(default_proto_version);
    info_cache_packet.WriteString(server_name);
    info_cache_packet.WriteString(map_name);
    info_cache_packet.WriteString(game_dir);
    info_cache_packet.WriteString(game_desc);
    info_cache_packet.WriteShort(appid);
    info_cache_packet.WriteByte(num_clients);
    info_cache_packet.WriteByte(max_players);
    info_cache_packet.WriteByte(num_fake_clients);
    info_cache_packet.WriteByte('d'); // dedicated
    info_cache_packet.WriteByte(operating_system_char);
    info_cache_packet.WriteByte(has_password ? 1 : 0);
    info_cache_packet.WriteByte(static_cast<int>(vac_secure));
    info_cache_packet.WriteString(game_version);
    // 0x80 - port
    // 0x10 - server steamid
    // 0x20 - tags
    // 0x01 - long appid
    info_cache_packet.WriteByte(0x80 | 0x10 | (has_tags ? 0x20 : 0x00) | 0x01);
    info_cache_packet.WriteShort(udp_port);
    info_cache_packet.WriteLongLong(static_cast<int64_t>(steamid));
    if (has_tags) {
      info_cache_packet.WriteString(tags.c_str());
    }
    info_cache_packet.WriteLongLong(appid);
  }

  void BuildReplyPlayer(reply_player_t info) {
    player_cache_packet.Reset();

    player_cache_packet.WriteLong(-1);
    player_cache_packet.WriteByte('D');

    player_cache_packet.WriteByte(info.count);

    for (int c = 0; c < info.count; c++) {
      player_t player = info.players[c];
      player_cache_packet.WriteByte(c);
      player_cache_packet.WriteString(player.name.c_str());
      player_cache_packet.WriteLong(static_cast<int32_t>(player.score));
      player_cache_packet.WriteFloat(static_cast<float>(player.time));
    }
  }

  void SetFirewallWhitelistState(const bool enabled) {
    firewall_whitelist_enabled = enabled;
  }

  // Whitelisted IPs bytes need to be in network order (big endian)
  void AddWhitelistIP(const uint32_t address) {
    firewall_whitelist.insert(address);
  }

  void RemoveWhitelistIP(const uint32_t address) {
    firewall_whitelist.erase(address);
  }

  void ResetWhitelist() {
    std::unordered_set<uint32_t>().swap(firewall_whitelist);
  }

  void SetFirewallBlacklistState(const bool enabled) {
    firewall_blacklist_enabled = enabled;
  }

  // Blacklisted IPs bytes need to be in network order (big endian)
  void AddBlacklistIP(const uint32_t address) {
    firewall_blacklist.insert(address);
  }

  void RemoveBlacklistIP(const uint32_t address) {
    firewall_blacklist.erase(address);
  }

  void ResetBlacklist() {
    std::unordered_set<uint32_t>().swap(firewall_blacklist);
  }

  void SetPacketValidationState(const bool enabled) {
    packet_validation_enabled = enabled;
  }

  void SetInfoCacheState(const bool enabled) { info_cache_enabled = enabled; }
  void SetInfoCacheTime(const uint32_t time) { info_cache_time = time; }

  bool PopPacketFromSamplingQueue(packet_t &p) {
    AUTO_LOCK(packet_sampling_mutex);

    if (packet_sampling_queue.empty()) {
      return false;
    }

    p = std::move(packet_sampling_queue.front());
    packet_sampling_queue.pop();
    return true;
  }

  void SetPacketSamplingState(bool enabled) {
    packet_sampling_enabled = enabled;

    if (!enabled) {
      AUTO_LOCK(packet_sampling_mutex);
      std::queue<packet_t>().swap(packet_sampling_queue);
    }
  }

  ClientManager &GetClientManager() { return client_manager; }

  static std::unique_ptr<Core> Singleton;

private:
  struct reply_info_t {
    std::string game_dir;
    std::string game_version;
    std::string game_desc;
    int32_t max_clients = 0;
    int32_t udp_port = 0;
    server_tags_t tags;
  };

  enum class PacketType { Invalid = -1, Good, Info, Player };

  using recvfrom_t = ssize_t(SERVERSECURE_CALLING_CONVENTION *)(
      SOCKET, void *, recvlen_t, int32_t, sockaddr *, socklen_t *);

#if defined SYSTEM_WINDOWS
  static constexpr char operating_system_char = 'w';
#elif defined SYSTEM_MACOSX
  static constexpr char operating_system_char = 'm';
#else
  static constexpr char operating_system_char = 'l';
#endif

  static constexpr size_t threaded_socket_max_buffer = 8192;
  static constexpr size_t threaded_socket_max_queue = 1000;

  static constexpr std::string_view default_game_version = "2020.10.14";
  static constexpr uint8_t default_proto_version = 17;
  static constexpr uint8_t default_netproto_version = 24;

  static constexpr size_t packet_sampling_max_queue = 50;

  // Max size needed to contain a Steam authentication key (both server and client)
  static constexpr int16_t STEAM_KEYSIZE = 2048;

  static constexpr int32_t PROTOCOL_STEAM = 0x03;

  IServer *server = nullptr;
  ISteamGameServer *gameserver = nullptr;

  SourceSDK::FactoryLoader icvar_loader = SourceSDK::FactoryLoader("vstdlib");
  ConVar *sv_visiblemaxplayers = nullptr;
  ConVar *sv_location = nullptr;

  SourceSDK::ModuleLoader dedicated_loader = SourceSDK::ModuleLoader("dedicated");
  SourceSDK::FactoryLoader server_loader = SourceSDK::FactoryLoader("server");

#ifdef PLATFORM_WINDOWS
  Detouring::Hook recvfrom_hook =
      Detouring::Hook("ws2_32", "recvfrom", reinterpret_cast<void *>(recvfrom_detour));
#else
  Detouring::Hook recvfrom_hook =
      Detouring::Hook("recvfrom", reinterpret_cast<void *>(recvfrom_detour));
#endif

  SOCKET game_socket = INVALID_SOCKET;

  bool packet_validation_enabled = false;

  bool firewall_whitelist_enabled = false;
  std::unordered_set<uint32_t> firewall_whitelist;

  bool firewall_blacklist_enabled = false;
  std::unordered_set<uint32_t> firewall_blacklist;

  bool threaded_socket_execute = true;
  ThreadHandle_t threaded_socket_handle = nullptr;
  std::queue<packet_t> threaded_socket_queue;
  CThreadFastMutex threaded_socket_mutex;

  bool info_cache_enabled = false;
  reply_info_t reply_info;
  std::array<char, 1024> info_cache_buffer{};
  bf_write info_cache_packet =
      bf_write(info_cache_buffer.data(), static_cast<int32_t>(info_cache_buffer.size()));
  uint32_t info_cache_last_update = 0;
  uint32_t info_cache_time = 5;

  uint32_t info_cache_players_last_update = 0;
  uint32_t info_cache_players_time = 5;

  reply_player_t reply_player;
  std::array<char, 1024 * 5> player_cache_buffer{};
  bf_write player_cache_packet =
      bf_write(player_cache_buffer.data(), static_cast<int32_t>(player_cache_buffer.size()));

  // буфер для кастомного A2S_INFO с оверрайдом карты
  std::array<char, 1024> custom_info_buffer{};

  ClientManager client_manager;

  bool packet_sampling_enabled = false;
  std::queue<packet_t> packet_sampling_queue;
  CThreadFastMutex packet_sampling_mutex;

  IServerGameDLL *gamedll = nullptr;
  IVEngineServer *engine_server = nullptr;
  IFileSystem *filesystem = nullptr;

  static inline const char *IPToString(const in_addr &addr) {
    static std::array<char, INET_ADDRSTRLEN> buffer{};
    const char *str = inet_ntop(AF_INET, &addr, buffer.data(), buffer.size());
    if (str == nullptr) {
      return "unknown";
    }
    return str;
  }

  // --------- Lua hooks ---------

  // A2S_PLAYER → вернуть false, чтобы не слать, вернуть таблицу игроков для подмены,
  // иначе (true/nil) — отдать дефолтный ответ сервера
  reply_player_t CallPlayerHook(const sockaddr_in &from) {
    reply_player_t players;
    players.dontsend = false;
    players.senddefault = true;

    // only in main thread with valid lua
    if (server_lua == nullptr || !InMainThread())
      return players;

    int initial_stack = server_lua->Top();

    char hook_name[] = "A2S_PLAYER";
    server_lua->GetField(GarrysMod::Lua::INDEX_GLOBAL, "hook");
    if (!server_lua->IsType(-1, GarrysMod::Lua::Type::TABLE)) {
      Warning("[gmsv_serversecure] Global hook is not a table!\n");
      server_lua->Pop(1);
      return players;
    }

    server_lua->GetField(-1, "Run");
    server_lua->Remove(-2);
    if (!server_lua->IsType(-1, GarrysMod::Lua::Type::FUNCTION)) {
      Warning("[gmsv_serversecure] hook.Run is not a function!\n");
      server_lua->Pop(1);
      return players;
    }

    server_lua->PushString(hook_name);
    server_lua->PushString(IPToString(from.sin_addr));
    server_lua->PushNumber(ntohs(from.sin_port));
    if (server_lua->PCall(3, 1, 0) != 0) {
      Warning("[gmsv_serversecure] A2S_PLAYER error: %s\n", server_lua->GetString());
    }

    if (server_lua->IsType(-1, GarrysMod::Lua::Type::BOOL)) {
      if (!server_lua->GetBool(-1)) {
        players.senddefault = false;
        players.dontsend = true;
      }
    } else if (server_lua->IsType(-1, GarrysMod::Lua::Type::TABLE)) {
      players.senddefault = false;

      int count = server_lua->ObjLen(-1);
      if (count < 0) count = 0;
      players.count = static_cast<byte>(count);

      std::vector<player_t> newPlayers(static_cast<size_t>(count));

      for (int i = 0; i < count; i++) {
        player_t newPlayer{};
        newPlayer.index = static_cast<byte>(i);

        server_lua->PushNumber(i + 1);
        server_lua->GetTable(-2);

        server_lua->GetField(-1, "name");
        newPlayer.name = server_lua->GetString(-1);
        server_lua->Pop(1);

        server_lua->GetField(-1, "score");
        newPlayer.score = server_lua->GetNumber(-1);
        server_lua->Pop(1);

        server_lua->GetField(-1, "time");
        newPlayer.time = server_lua->GetNumber(-1);
        server_lua->Pop(1);

        server_lua->Pop(1);
        newPlayers.at(static_cast<size_t>(i)) = newPlayer;
      }

      players.players = std::move(newPlayers);
    }

    server_lua->Pop(1);

    if (server_lua->Top() != initial_stack) {
      Warning("[gmsv_serversecure] Stack leak detected in A2S_PLAYER: %d -> %d\n",
              initial_stack, server_lua->Top());
    }

    return players;
  }

  // A2S_MAP → вернуть false, чтобы не слать, вернуть строку для оверрайда карты,
  // иначе (true/nil) — дефолтный ответ
  reply_map_t CallMapHook(const sockaddr_in &from) {
    reply_map_t res;
    res.dontsend = false;
    res.senddefault = true;
    res.map.clear();

    if (server_lua == nullptr || !InMainThread())
      return res;

    int initial_stack = server_lua->Top();

    char hook_name[] = "A2S_MAP";
    server_lua->GetField(GarrysMod::Lua::INDEX_GLOBAL, "hook");
    if (!server_lua->IsType(-1, GarrysMod::Lua::Type::TABLE)) {
      Warning("[gmsv_serversecure] Global hook is not a table!\n");
      server_lua->Pop(1);
      return res;
    }

    server_lua->GetField(-1, "Run");
    server_lua->Remove(-2);
    if (!server_lua->IsType(-1, GarrysMod::Lua::Type::FUNCTION)) {
      Warning("[gmsv_serversecure] hook.Run is not a function!\n");
      server_lua->Pop(1);
      return res;
    }

    server_lua->PushString(hook_name);
    server_lua->PushString(IPToString(from.sin_addr));
    server_lua->PushNumber(ntohs(from.sin_port));
    if (server_lua->PCall(3, 1, 0) != 0) {
      Warning("[gmsv_serversecure] A2S_MAP error: %s\n", server_lua->GetString());
    }

    if (server_lua->IsType(-1, GarrysMod::Lua::Type::BOOL)) {
      if (!server_lua->GetBool(-1)) {
        res.senddefault = false;
        res.dontsend = true;
      }
    } else if (server_lua->IsType(-1, GarrysMod::Lua::Type::STRING)) {
      res.senddefault = false;
      res.map = server_lua->GetString(-1);
    }

    server_lua->Pop(1);

    if (server_lua->Top() != initial_stack) {
      Warning("[gmsv_serversecure] Stack leak detected in A2S_MAP: %d -> %d\n",
              initial_stack, server_lua->Top());
    }

    return res;
  }

  // --------- A2S helpers ---------

  PacketType SendInfoCache(const sockaddr_in &from, uint32_t time) {
    if (time - info_cache_last_update >= info_cache_time) {
      BuildReplyInfo();
      info_cache_last_update = time;
    }

    sendto(game_socket, reinterpret_cast<char *>(info_cache_packet.GetData()),
           info_cache_packet.GetNumBytesWritten(), 0,
           reinterpret_cast<const sockaddr *>(&from), sizeof(from));

    DevMsg(2, "[ServerSecure] Handled %s info request using cache\n",
           IPToString(from.sin_addr));

    return PacketType::Invalid; // handled
  }

  PacketType SendInfoChallenge(const sockaddr_in &from) {
    uint8_t challenge_pkt[4 + 1 + 4] {0};
    const uint32_t header = 0xFFFFFFFFu;
    std::memcpy(challenge_pkt + 0, &header, sizeof(header));
    challenge_pkt[4] = 'A';
    netadr_t net_addr(from.sin_addr.s_addr, from.sin_port);
    const uint32_t chal =
        static_cast<uint32_t>(CBaseServerProxy::Singleton->GetChallengeNr(net_addr));
    std::memcpy(challenge_pkt + 5, &chal, sizeof(chal));

    sendto(game_socket, reinterpret_cast<char *>(challenge_pkt),
           sizeof(challenge_pkt), 0,
           reinterpret_cast<const sockaddr *>(&from), sizeof(from));
    return PacketType::Invalid;
  }

  // собрать и отправить A2S_INFO с кастомным названием карты
  PacketType SendInfoWithCustomMap(const sockaddr_in &from, const char *map_override) {
    const char *server_name = server->GetName();
    const char *game_dir = reply_info.game_dir.c_str();
    const char *game_desc = reply_info.game_desc.c_str();
    const int32_t appid = engine_server->GetAppID();
    const int32_t num_clients = server->GetNumClients();

    int32_t max_players =
        sv_visiblemaxplayers != nullptr ? sv_visiblemaxplayers->GetInt() : -1;
    if (max_players <= 0 || max_players > reply_info.max_clients) {
      max_players = reply_info.max_clients;
    }

    const int32_t num_fake_clients = server->GetNumFakeClients();
    const bool has_password = server->GetPassword() != nullptr;

    if (gameserver == nullptr) {
      gameserver = SteamGameServer();
    }

    bool vac_secure = false;
    if (gameserver != nullptr) {
      vac_secure = gameserver->BSecure();
    }

    const char *game_version = reply_info.game_version.c_str();
    const int32_t udp_port = reply_info.udp_port;
    const CSteamID *sid = engine_server->GetGameServerSteamID();
    const uint64_t steamid = sid != nullptr ? sid->ConvertToUint64() : 0;

    if (sv_location != nullptr) {
      reply_info.tags.loc = sv_location->GetString();
    } else {
      reply_info.tags.loc.clear();
    }

    const std::string tags = ConcatenateTags(reply_info.tags);
    const bool has_tags = !tags.empty();

    bf_write w(custom_info_buffer.data(),
               static_cast<int32_t>(custom_info_buffer.size()));

    w.WriteLong(-1);
    w.WriteByte('I');
    w.WriteByte(default_proto_version);
    w.WriteString(server_name);
    w.WriteString(map_override != nullptr ? map_override : server->GetMapName());
    w.WriteString(game_dir);
    w.WriteString(game_desc);
    w.WriteShort(appid);
    w.WriteByte(num_clients);
    w.WriteByte(max_players);
    w.WriteByte(num_fake_clients);
    w.WriteByte('d');
    w.WriteByte(operating_system_char);
    w.WriteByte(has_password ? 1 : 0);
    w.WriteByte(static_cast<int>(vac_secure));
    w.WriteString(game_version);
    w.WriteByte(0x80 | 0x10 | (has_tags ? 0x20 : 0x00) | 0x01);
    w.WriteShort(udp_port);
    w.WriteLongLong(static_cast<int64_t>(steamid));
    if (has_tags) {
      w.WriteString(tags.c_str());
    }
    w.WriteLongLong(appid);

    // Проверяем переполнение
    if (w.IsOverflowed()) {
      DevWarning("[ServerSecure] A2S_MAP: packet overflow (%d bytes)\n",
                 w.GetNumBytesWritten());
      return PacketType::Invalid;
    }

    sendto(game_socket,
           reinterpret_cast<char*>(w.GetData()),
           w.GetNumBytesWritten(),
           0,
           reinterpret_cast<const sockaddr*>(&from),
           sizeof(from));

    DevMsg(2, "[ServerSecure] Handled %s info request with custom map\n",
           IPToString(from.sin_addr));

    return PacketType::Invalid; // handled
  }

  // main classifier → Info / Player / Good/Invalid
  PacketType ClassifyPacket(const uint8_t *data, int32_t len,
                            const sockaddr_in &from) {
    if (len == 0) {
      DevWarning("[ServerSecure] Bad OOB! len: %d from %s\n", len,
                 IPToString(from.sin_addr));
      return PacketType::Invalid;
    }

    if (len < 5) {
      return PacketType::Good;
    }

    bf_read packet(data, len);
    const auto channel = static_cast<int32_t>(packet.ReadLong());
    if (channel == -2) {
      DevWarning("[ServerSecure] Bad OOB! len: %d, channel: 0x%X from %s\n",
                 len, channel, IPToString(from.sin_addr));
      return PacketType::Invalid;
    }

    if (channel != -1) {
      return PacketType::Good;
    }

    const auto type = static_cast<uint8_t>(packet.ReadByte());

    if (packet_validation_enabled) {
      switch (type) {
      case 'W': // server challenge request
      case 's': // master server challenge
        if (len > 100) {
          DevWarning("[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
                     len, channel, type, IPToString(from.sin_addr));
          return PacketType::Invalid;
        }
        return PacketType::Good;

      case 'T': // A2S_INFO
        if ((len != 25 && len != 29 && len != 1200) ||
            strncmp(reinterpret_cast<const char *>(data + 5),
                    "Source Engine Query", 19) != 0) {
          DevWarning("[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
                     len, channel, type, IPToString(from.sin_addr));
          return PacketType::Invalid;
        }
        return PacketType::Info;

      case 'U': // A2S_PLAYER
        return PacketType::Player;

      case 'V': // A2S_RULES
        if (len != 9 && len != 1200) {
          DevWarning("[ServerSecure] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
                     len, channel, type, IPToString(from.sin_addr));
          return PacketType::Invalid;
        }
        return PacketType::Good;

      case 'q': // connection handshake init
        return PacketType::Good;

      case 'k': // steam auth
      {
        const int32_t protocol = packet.ReadLong();
        if (protocol != default_netproto_version) {
          DevWarning("[ServerSecure] Bad protocol number from %s\n",
                     IPToString(from.sin_addr));
          return PacketType::Invalid;
        }

        const int32_t authProtocol = packet.ReadLong();
        if (authProtocol != PROTOCOL_STEAM) {
          DevWarning("[ServerSecure] Bad authentication protocol from %s\n",
                     IPToString(from.sin_addr));
          return PacketType::Invalid;
        }

        const int32_t challengeNr = packet.ReadLong();

        netadr_t netaddr{};
        netaddr.SetFromSockadr(reinterpret_cast<const sockaddr *>(&from));
        if (!CheckChallengeNr(netaddr, challengeNr)) {
          DevWarning("[ServerSecure] Bad connection challenge from %s\n",
                     IPToString(from.sin_addr));
          return PacketType::Invalid;
        }

        const auto time = static_cast<uint32_t>(Plat_FloatTime());
        const auto rate_limit = client_manager.CheckIPRate(from.sin_addr.s_addr, time);
        if (rate_limit != ClientManager::RateLimitType::None) {
          return PacketType::Invalid;
        }

        // skip rest
        return PacketType::Good;
      }

      default:
        DevWarning("[ServerSecure] Bad OOB type: %c\n", type);
        return PacketType::Invalid;
      }
    }

    return type == 'T' ? PacketType::Info
                       : (type == 'U' ? PacketType::Player : PacketType::Good);
  }

  PacketType HandleInfoQuery(const uint8_t* buffer,
                             ssize_t length,
                             const sockaddr_in &from) {
    const auto time = static_cast<uint32_t>(Plat_FloatTime());
    const auto rate_limit = client_manager.CheckIPRate(from.sin_addr.s_addr, time);
    if (rate_limit != ClientManager::RateLimitType::None) {
      DevWarning("[ServerSecure] Client %s hit %s rate limit\n",
                 IPToString(from.sin_addr),
                 rate_limit == ClientManager::RateLimitType::Individual ? "individual" : "global");
      return PacketType::Invalid;
    }

    // If no challenge provided (25 bytes), reply with 'A' challenge
    if (length == 25) {
      return SendInfoChallenge(from);
    }

    // If challenge provided (29 or junk with 1200), verify
    constexpr ssize_t CHALLENGE_OFFSET = 4 + 1 + 19 + 1; // -1, 'T', "Source Engine Query", '\0'
    if (length >= CHALLENGE_OFFSET + 4) {
      uint32_t challenge = 0;
      std::memcpy(&challenge, buffer + CHALLENGE_OFFSET, sizeof(challenge));
      netadr_t net_addr(from.sin_addr.s_addr, from.sin_port);
      if (!CBaseServerProxy::Singleton->CheckChallengeNr(net_addr, static_cast<int>(challenge))) {
        return SendInfoChallenge(from);
      }
    }

    // Map override hook
    const reply_map_t map_res = CallMapHook(from);
    if (map_res.dontsend) {
      return PacketType::Invalid;
    }
    if (!map_res.senddefault) {
      return SendInfoWithCustomMap(from, map_res.map.c_str());
    }

    if (info_cache_enabled) {
      return SendInfoCache(from, time);
    }

    return PacketType::Good;
  }

  PacketType HandlePlayerQuery(const uint8_t* /*buffer*/,
                               ssize_t /*length*/,
                               const sockaddr_in &from) {
    const auto time = static_cast<uint32_t>(Plat_FloatTime());
    const auto rate_limit = client_manager.CheckIPRate(from.sin_addr.s_addr, time);
    if (rate_limit != ClientManager::RateLimitType::None) {
      DevWarning("[ServerSecure] Client %s hit %s rate limit\n",
                 IPToString(from.sin_addr),
                 rate_limit == ClientManager::RateLimitType::Individual ? "individual" : "global");
      return PacketType::Invalid;
    }

    if (time - info_cache_players_last_update >= info_cache_players_time) {
      info_cache_players_last_update = time;

      ch_players = CallPlayerHook(from);

      if (ch_players.senddefault)
        return PacketType::Good;

      if (ch_players.dontsend)
        return PacketType::Invalid;

      BuildReplyPlayer(ch_players);
    }

    if (ch_players.senddefault)
      return PacketType::Good;

    if (ch_players.dontsend)
      return PacketType::Invalid;

    sendto(game_socket, reinterpret_cast<char *>(player_cache_packet.GetData()),
           player_cache_packet.GetNumBytesWritten(), 0,
           reinterpret_cast<const sockaddr *>(&from), sizeof(from));

    return PacketType::Invalid;
  }

  bool IsAddressAllowed(const sockaddr_in &addr) {
    return (!firewall_whitelist_enabled ||
            firewall_whitelist.find(addr.sin_addr.s_addr) != firewall_whitelist.end()) &&
           (!firewall_blacklist_enabled ||
            firewall_blacklist.find(addr.sin_addr.s_addr) == firewall_blacklist.end());
  }

  static int32_t HandleNetError(int32_t value) {
    if (value == -1) {
#if defined SYSTEM_WINDOWS
      WSASetLastError(WSAEWOULDBLOCK);
#elif defined SYSTEM_POSIX
      errno = EWOULDBLOCK;
#endif
    }
    return value;
  }

  bool IsPacketQueueFull() {
    AUTO_LOCK(threaded_socket_mutex);
    return threaded_socket_queue.size() >= threaded_socket_max_queue;
  }

  bool PopPacketFromQueue(packet_t &p) {
    AUTO_LOCK(threaded_socket_mutex);
    if (threaded_socket_queue.empty()) {
      return false;
    }
    p = std::move(threaded_socket_queue.front());
    threaded_socket_queue.pop();
    return true;
  }

  void PushPacketToQueue(packet_t &&p) {
    AUTO_LOCK(threaded_socket_mutex);
    threaded_socket_queue.emplace(std::move(p));
  }

  void PushPacketToSamplingQueue(packet_t &&p) {
    AUTO_LOCK(packet_sampling_mutex);

    if (packet_sampling_queue.size() >= packet_sampling_max_queue) {
      packet_sampling_queue.pop();
    }

    packet_sampling_queue.emplace(std::move(p));
  }

  // Только получить пакет с сокета (без анализа/хуков)
  ssize_t ReceivePacket(SOCKET s, void *buf, recvlen_t buflen,
                        int32_t flags, sockaddr *from,
                        socklen_t *fromlen) {
    auto trampoline = recvfrom_hook.GetTrampoline<recvfrom_t>();
    if (trampoline == nullptr) {
      return -1;
    }

    const ssize_t len = trampoline(s, buf, buflen, flags, from, fromlen);
    if (len == -1) {
      return -1;
    }

    return len;
  }

  ssize_t HandleDetour(SOCKET s, void *buf, recvlen_t buflen, int32_t flags,
                       sockaddr *from, socklen_t *fromlen) {
    if (s != game_socket) {
      auto trampoline = recvfrom_hook.GetTrampoline<recvfrom_t>();
      return trampoline != nullptr
                 ? trampoline(s, buf, buflen, flags, from, fromlen)
                 : -1;
    }

    packet_t p;
    const bool has_packet = PopPacketFromQueue(p);
    if (!has_packet) {
      return HandleNetError(-1);
    }

    // --- Классификация и хуки ТЕПЕРЬ здесь (главный поток) ---
    const sockaddr_in &infrom = *reinterpret_cast<sockaddr_in *>(&p.address);

    if (!IsAddressAllowed(infrom)) {
      DevWarning("[ServerSecure] Blocked packet from %s\n", IPToString(infrom.sin_addr));
      return HandleNetError(-1);
    }

    PacketType type = ClassifyPacket(p.buffer.data(),
                                     static_cast<int32_t>(p.buffer.size()),
                                     infrom);
    if (type == PacketType::Info) {
      type = HandleInfoQuery(p.buffer.data(),
                             static_cast<ssize_t>(p.buffer.size()),
                             infrom);
    } else if (type == PacketType::Player) {
      type = HandlePlayerQuery(p.buffer.data(),
                               static_cast<ssize_t>(p.buffer.size()),
                               infrom);
    }

    // Для sampling — уже после классификации (чтобы видеть только «живые» пакеты)
    if (packet_sampling_enabled && type != PacketType::Invalid) {
      packet_t cp = p;
      PushPacketToSamplingQueue(std::move(cp));
    }

    if (type == PacketType::Invalid) {
      return HandleNetError(-1);
    }

    const ssize_t len = (std::min)(static_cast<ssize_t>(p.buffer.size()),
                                   static_cast<ssize_t>(buflen));
    std::memcpy(buf, p.buffer.data(), static_cast<size_t>(len));

    const socklen_t addrlen = (std::min)(*fromlen, p.address_size);
    std::memcpy(from, &p.address, static_cast<size_t>(addrlen));
    *fromlen = addrlen;

    return len;
  }

  static ssize_t SERVERSECURE_CALLING_CONVENTION
  recvfrom_detour(SOCKET s, void *buf, recvlen_t buflen, int32_t flags,
                  sockaddr *from, socklen_t *fromlen) {
    return Singleton->HandleDetour(s, buf, buflen, flags, from, fromlen);
  }

  uintp HandleThread() {
    while (threaded_socket_execute) {
      if (IsPacketQueueFull()) {
        ThreadSleep(100);
        continue;
      }

      fd_set readables;
      FD_ZERO(&readables);
      FD_SET(game_socket, &readables);
      timeval timeout = {0, 100000};
      const int32_t res = select(static_cast<int32_t>(game_socket + 1),
                                 &readables, nullptr, nullptr, &timeout);
      if (res == -1 || !FD_ISSET(game_socket, &readables)) {
        continue;
      }

      packet_t p;
      p.buffer.resize(threaded_socket_max_buffer);
      const ssize_t len = ReceivePacket(
          game_socket, p.buffer.data(),
          static_cast<recvlen_t>(threaded_socket_max_buffer), 0,
          reinterpret_cast<sockaddr *>(&p.address), &p.address_size);
      if (len == -1) {
        continue;
      }

      p.buffer.resize(static_cast<size_t>(len));
      PushPacketToQueue(std::move(p));
    }

    return 0;
  }

  static void SetThreadName() {
#ifdef SYSTEM_WINDOWS
    using SetThreadDescription_t = decltype(&SetThreadDescription);
    const HMODULE kernel_base_module = GetModuleHandle("KernelBase.dll");
    if (kernel_base_module == nullptr) return;
    const auto SetThreadDescription_p =
        reinterpret_cast<SetThreadDescription_t>(
            GetProcAddress(kernel_base_module, "SetThreadDescription"));
    if (SetThreadDescription_p == nullptr) return;
    SetThreadDescription_p(GetCurrentThread(),
                           L"serversecure packet receiver/analyzer");
#elif SYSTEM_LINUX
    prctl(PR_SET_NAME, reinterpret_cast<unsigned long>("serversecure"), 0, 0, 0);
#elif SYSTEM_MACOSX
    pthread_setname_np("serversecure");
#endif
  }

  static uintp PacketReceiverThread(void *param) {
    SetThreadName();
    return static_cast<Core *>(param)->HandleThread();
  }
};

std::unique_ptr<Core> Core::Singleton;

// ---------- Lua-exposed functions (как и раньше) ----------

LUA_FUNCTION_STATIC(EnableFirewallWhitelist) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
  Core::Singleton->SetFirewallWhitelistState(LUA->GetBool(1));
  return 0;
}

LUA_FUNCTION_STATIC(AddWhitelistIP) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->AddWhitelistIP(static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(RemoveWhitelistIP) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->RemoveWhitelistIP(static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(ResetWhitelist) {
  Core::Singleton->ResetWhitelist();
  return 0;
}

LUA_FUNCTION_STATIC(EnableFirewallBlacklist) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
  Core::Singleton->SetFirewallBlacklistState(LUA->GetBool(1));
  return 0;
}

LUA_FUNCTION_STATIC(AddBlacklistIP) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->AddBlacklistIP(static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(RemoveBlacklistIP) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->RemoveBlacklistIP(static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(ResetBlacklist) {
  Core::Singleton->ResetBlacklist();
  return 0;
}

LUA_FUNCTION_STATIC(EnablePacketValidation) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
  Core::Singleton->SetPacketValidationState(LUA->GetBool(1));
  return 0;
}

LUA_FUNCTION_STATIC(EnableInfoCache) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
  Core::Singleton->SetInfoCacheState(LUA->GetBool(1));
  return 0;
}

LUA_FUNCTION_STATIC(SetInfoCacheTime) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->SetInfoCacheTime(static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(RefreshInfoCache) {
  Core::Singleton->BuildStaticReplyInfo(nullptr);
  Core::Singleton->BuildReplyInfo();
  return 0;
}

LUA_FUNCTION_STATIC(EnableQueryLimiter) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
  Core::Singleton->GetClientManager().SetState(LUA->GetBool(1));
  return 0;
}

LUA_FUNCTION_STATIC(SetMaxQueriesWindow) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->GetClientManager().SetMaxQueriesWindow(
      static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(SetMaxQueriesPerSecond) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->GetClientManager().SetMaxQueriesPerSecond(
      static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(SetGlobalMaxQueriesPerSecond) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Number);
  Core::Singleton->GetClientManager().SetGlobalMaxQueriesPerSecond(
      static_cast<uint32_t>(LUA->GetNumber(1)));
  return 0;
}

LUA_FUNCTION_STATIC(EnablePacketSampling) {
  LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
  Core::Singleton->SetPacketSamplingState(LUA->GetBool(1));
  return 0;
}

LUA_FUNCTION_STATIC(GetSamplePacket) {
  Core::packet_t p;
  if (!Core::Singleton->PopPacketFromSamplingQueue(p)) {
    return 0;
  }

  LUA->PushNumber(p.address.sin_addr.s_addr);
  LUA->PushNumber(p.address.sin_port);
  LUA->PushString(reinterpret_cast<const char *>(&p.buffer[0]),
                  static_cast<unsigned int>(p.buffer.size()));
  return 3;
}

// ---------- entry points ----------

void Initialize(GarrysMod::Lua::ILuaBase *LUA) {
  server_lua = LUA;

  // main thread id
#if defined(SYSTEM_WINDOWS)
  g_main_tid = GetCurrentThreadId();
#else
  g_main_tid = pthread_self();
#endif

  LUA->GetField(GarrysMod::Lua::INDEX_GLOBAL, "VERSION");
  const char *game_version = LUA->CheckString(-1);

  bool errored = false;
  try {
    Core::Singleton = std::make_unique<Core>(game_version);
  } catch (const std::exception &e) {
    errored = true;
    LUA->PushString(e.what());
  }

  if (errored) {
    LUA->Error();
  }

  LUA->Pop(1);

  auto *baseserver = dynamic_cast<CBaseServer *>(InterfacePointers::Server());
  if (baseserver != nullptr) {
    CBaseServerProxy::Singleton =
        std::make_unique<CBaseServerProxy>(baseserver);
  }

  LUA->PushCFunction(EnableFirewallWhitelist);   LUA->SetField(-2, "EnableFirewallWhitelist");
  LUA->PushCFunction(AddWhitelistIP);            LUA->SetField(-2, "AddWhitelistIP");
  LUA->PushCFunction(RemoveWhitelistIP);         LUA->SetField(-2, "RemoveWhitelistIP");
  LUA->PushCFunction(ResetWhitelist);            LUA->SetField(-2, "ResetWhitelist");

  LUA->PushCFunction(EnableFirewallBlacklist);   LUA->SetField(-2, "EnableFirewallBlacklist");
  LUA->PushCFunction(AddBlacklistIP);            LUA->SetField(-2, "AddBlacklistIP");
  LUA->PushCFunction(RemoveBlacklistIP);         LUA->SetField(-2, "RemoveBlacklistIP");
  LUA->PushCFunction(ResetBlacklist);            LUA->SetField(-2, "ResetBlacklist");

  LUA->PushCFunction(EnablePacketValidation);    LUA->SetField(-2, "EnablePacketValidation");

  LUA->PushCFunction(EnableInfoCache);           LUA->SetField(-2, "EnableInfoCache");
  LUA->PushCFunction(SetInfoCacheTime);          LUA->SetField(-2, "SetInfoCacheTime");
  LUA->PushCFunction(RefreshInfoCache);          LUA->SetField(-2, "RefreshInfoCache");

  LUA->PushCFunction(EnableQueryLimiter);        LUA->SetField(-2, "EnableQueryLimiter");
  LUA->PushCFunction(SetMaxQueriesWindow);       LUA->SetField(-2, "SetMaxQueriesWindow");
  LUA->PushCFunction(SetMaxQueriesPerSecond);    LUA->SetField(-2, "SetMaxQueriesPerSecond");
  LUA->PushCFunction(SetGlobalMaxQueriesPerSecond); LUA->SetField(-2, "SetGlobalMaxQueriesPerSecond");

  LUA->PushCFunction(EnablePacketSampling);      LUA->SetField(-2, "EnablePacketSampling");
  LUA->PushCFunction(GetSamplePacket);           LUA->SetField(-2, "GetSamplePacket");
}

void Deinitialize() {
  CBaseServerProxy::Singleton.reset();
  Core::Singleton.reset();
}

} // namespace netfilter
