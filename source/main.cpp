#include "filecheck.hpp"
#include "netfilter/core.hpp"

#include <GarrysMod/InterfacePointers.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <Platform.hpp>

#include <convar.h>
#include <iserver.h>

#include <cstdint>
#include <string>

namespace global {

static constexpr std::string_view Version = "serversecure 1.5.42";
static constexpr uint32_t VersionNum = 10542;

static IServer *server = nullptr;
static ICvar *cvar = nullptr;

LUA_FUNCTION_STATIC(GetClientCount)
{
    LUA->PushNumber(server->GetClientCount());
    return 1;
}

LUA_FUNCTION_STATIC(GetServerPassword)
{
    if (cvar == nullptr)
    {
        LUA->PushNil();
        return 1;
    }

    ConVar *sv_password = cvar->FindVar("sv_password");
    if (sv_password == nullptr)
    {
        LUA->PushNil();
        return 1;
    }

    LUA->PushString(sv_password->GetString());
    return 1;
}

LUA_FUNCTION_STATIC(IsServerHasPassword)
{
    if (cvar == nullptr)
    {
        LUA->PushBool(false);
        return 1;
    }

    ConVar *sv_password = cvar->FindVar("sv_password");
    if (sv_password == nullptr)
    {
        LUA->PushBool(false);
        return 1;
    }

    const char *pwd = sv_password->GetString();
    bool has_password = (pwd != nullptr && pwd[0] != '\0');
    LUA->PushBool(has_password);
    return 1;
}

static void PreInitialize(GarrysMod::Lua::ILuaBase *LUA)
{
    server = InterfacePointers::Server();
    if (server == nullptr)
    {
        LUA->ThrowError("failed to dereference IServer");
    }

    cvar = InterfacePointers::Cvar();
    if (cvar == nullptr)
    {
        LUA->ThrowError("failed to retrieve ICVar");
    }

    ConVar_Register();

    LUA->CreateTable();

    LUA->PushString(Version.data());
    LUA->SetField(-2, "Version");

    LUA->PushNumber(VersionNum);
    LUA->SetField(-2, "VersionNum");

    LUA->PushCFunction(GetClientCount);
    LUA->SetField(-2, "GetClientCount");

    LUA->PushCFunction(GetServerPassword);
    LUA->SetField(-2, "GetServerPassword");

    LUA->PushCFunction(IsServerHasPassword);
    LUA->SetField(-2, "IsServerHasPassword");
}

static void Initialize(GarrysMod::Lua::ILuaBase *LUA)
{
    LUA->SetField(GarrysMod::Lua::INDEX_GLOBAL, "serversecure");
}

static void Deinitialize(GarrysMod::Lua::ILuaBase *LUA)
{
    LUA->PushNil();
    LUA->SetField(GarrysMod::Lua::INDEX_GLOBAL, "serversecure");
}

} // namespace global

GMOD_MODULE_OPEN()
{
    global::PreInitialize(LUA);
    netfilter::Initialize(LUA);
    filecheck::Initialize(LUA);
    global::Initialize(LUA);
    return 1;
}

GMOD_MODULE_CLOSE()
{
    filecheck::Deinitialize();
    netfilter::Deinitialize();
    global::Deinitialize(LUA);
    return 0;
}
