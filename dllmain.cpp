#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cmath>
#include "MinHook.h"

#pragma comment(lib, "ws2_32.lib")

// ============================================================
// CONFIG
// ============================================================
#define INSTANCE_1_PORT 9001
#define INSTANCE_2_PORT 9002
#define RECON_DUMP_LIMIT 5   // nb de spawns dump en full avant de passer en mode resume

// Offsets connus (deja valides en runtime, calcules depuis base)
#define OFF_NETEVENT_CHARMOVE_EXEC   0x3DBE90
#define OFF_LOCOMOTION_UPDATE        0x1F7ACA0
#define OFF_SCHEMA_RESPAWNER_SPAWN   0x442B80
#define OFF_INIT_RESPAWNER           0x4423C0

// TODO: a calculer dans IDA -> Edit > Segments pour avoir l'image base statique,
// puis offset = adresse_statique - image_base_statique
//   SendNetEventNpcSpawn::Execute    statique = 7FF6D847D7A0
//   SendNetEventNpcSpawn(...)        statique = 7FF6D847D8B0
#define OFF_NETEVENT_NPCSPAWN_EXECUTE 0x9ED4F0   // confirme: prologue mov[rsp+18],rbx / push rbp,rdi,r14 / sub rsp,400, precede d'int3 padding
#define OFF_SEND_NETEVENT_NPCSPAWN    0x9EF4F0   // confirme: prologue push rbx/rbp/rsi/rdi/r15 + sub rsp,40 precede d'int3 padding
// NOTE: les 2 hooks ci-dessus sont la route MULTIJOUEUR (Factions, code mort en solo).
// Aucun des deux ne se declenche en jeu solo -> on cible desormais la vraie route
// generique de spawn, empruntee par TOUS les process (joueur, NPC, infectes), solo inclus.
//
// TODO: a calculer dans x64dbg -> trouver le vrai prologue de fonction en remontant
// depuis le call-site jusqu'au bloc push/sub rsp precede d'int3, comme fait pour
// NetEventNpcSpawn::Execute. Call-sites de reference (juste le lea de l'assert, PAS
// le debut de fonction):
//   Process::SpawnProcess(const ProcessSpawnInfo&, Err*)   call-site statique = 7FF6D6CD9CCA
//   Npc::Init(const ProcessSpawnInfo&)                      call-site statique = 7FF6D5D0E533
#define OFF_PROCESS_SPAWNPROCESS       0x14C9BB0 // confirme: prologue mov[rsp+18],rbx / push rbp,rsi,rdi,r12-r15 / sub rsp,210, precede d'int3 padding
#define OFF_NPC_INIT                   0x4FB510 // confirme: prologue push rbx,rsi,rdi,r12-r15 / sub rsp,650, precede d'int3. ATTENTION 3 params (rcx,rdx,r8), pas 2
// TrySpawnPlayerAtContinue(int charIndex, const DC::Continue&, const Locator*, const Locator*, const GameSave::PlayerCheckpoint*)
// -> TypedProcessHandle<Process>. Retour par struct trop gros pour rax => pointeur de retour cache en rcx,
// tout decale d'un cran: rcx=retval*, rdx=charIndex(int), r8=Continue&, r9=Locator*, pile=Locator*+PlayerCheckpoint*.
// C'est LE point d'entree natif qui spawn le joueur (Ellie) a un checkpoint -- piste pour spawn une 2e instance.
#define OFF_TRYSPAWN_PLAYER_AT_CONTINUE 0xDC1440 // confirme: prologue push rbx,rsi,rdi,r12-r15 / sub rsp,270, precede d'int3

// ============================================================
// ETAT GLOBAL
// ============================================================
static int myPort = 0;
static int remotePort = 0;
static SOCKET udpSocket = INVALID_SOCKET;
static void* companionObj = nullptr;

// ============================================================
// Validation memoire via VirtualQuery
// ============================================================
static bool IsPageReadable(const MEMORY_BASIC_INFORMATION& mbi) {
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & PAGE_GUARD) return false;
    DWORD base = mbi.Protect & 0xFF;
    return base != PAGE_NOACCESS && base != 0;
}

static bool TryReadString(const void* ptr, char* out, size_t maxLen) {
    if (!ptr || (uintptr_t)ptr < 0x10000) return false;

    const char* p = (const char*)ptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    uintptr_t pageEnd = 0;
    bool pageOk = false;

    size_t i = 0;
    for (; i < maxLen - 1; i++) {
        uintptr_t cur = (uintptr_t)(p + i);
        if (cur >= pageEnd) {
            if (VirtualQuery((LPCVOID)cur, &mbi, sizeof(mbi)) == 0) return false;
            pageOk = IsPageReadable(mbi);
            pageEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        }
        if (!pageOk) return false;
        char c = p[i];
        if (c == '\0') break;
        if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E) return false;
        out[i] = c;
    }
    out[i] = '\0';
    return i >= 3;
}

static void HexDump(const char* label, void* ptr, size_t len) {
    if (!ptr) { printf("[%s] ptr null\n", label); return; }
    unsigned char* p = (unsigned char*)ptr;
    printf("[%s] dump @ %p (%zu bytes):\n", label, ptr, len);

    MEMORY_BASIC_INFORMATION mbi = {};
    uintptr_t pageEnd = 0;
    bool pageOk = false;

    auto CheckPage = [&](uintptr_t addr) -> bool {
        if (addr >= pageEnd) {
            if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) { pageOk = false; return false; }
            pageOk = IsPageReadable(mbi);
            pageEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        }
        return pageOk;
    };

    for (size_t i = 0; i < len; i += 16) {
        printf("  +%03zx: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len && CheckPage((uintptr_t)(p + i + j))) printf("%02X ", p[i + j]);
            else if (i + j < len) printf("?? ");
            else printf("   ");
        }
        printf(" | ");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            if (CheckPage((uintptr_t)(p + i + j))) {
                unsigned char c = p[i + j];
                printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
            } else {
                printf("?");
            }
        }
        printf("\n");
    }

    printf("[%s] pointeurs -> strings trouves:\n", label);
    for (size_t i = 0; i + sizeof(void*) <= len; i += sizeof(void*)) {
        if (!CheckPage((uintptr_t)(p + i))) continue;
        void* candidate = *(void**)(p + i);
        char buf[128];
        if (TryReadString(candidate, buf, sizeof(buf))) {
            printf("  +%03zx -> %p \"%s\"\n", i, candidate, buf);
        }
    }
}

// ============================================================
// Hook 1 — NetEventCharacterMove::Execute
// ============================================================
typedef void* (*NetEventCharMove_t)(void* netEvent);
NetEventCharMove_t originalExecute = nullptr;

void* HookedExecute(void* netEvent) {
    if (netEvent) {
        uint32_t charId = *(uint32_t*)((char*)netEvent + 0x18);
        printf("[EXECUTE] CharID=%u\n", charId);
    }
    return originalExecute(netEvent);
}

// ============================================================
// Hook 2 — CharacterMotionMatchLocomotion::Update
// + detection temps reel de nouvelles entites
// + consommation du flag de spawn manuel (cf. Hook 9 / HotkeyThread)
// ============================================================
typedef void* (*LocoUpdate_t)(void* locoObj, float deltaTime, void* ctx);
LocoUpdate_t originalLocoUpdate = nullptr;

static int locoFrameCounter = 0;
static void* ellieObj = nullptr;
static void* candidates[16] = {};
static int candidateCounts[16] = {};

static float remoteX = 0, remoteY = 0, remoteZ = 0;
static bool hasRemote = false;

enum PacketType : uint32_t { PKT_POS = 1, PKT_SPAWN_TRIGGER = 2 };
struct PosPacket { uint32_t type; float x, y, z; };

static char seenNames[64][32] = {};
static void* lastLocoObj[64] = {};
static int seenNameCount = 0;

static int FindOrAddName(const char* nameBuf, bool* isNew) {
    for (int i = 0; i < seenNameCount; i++) {
        if (memcmp(seenNames[i], nameBuf, 32) == 0) {
            *isNew = false;
            return i;
        }
    }
    *isNew = true;
    if (seenNameCount < 64) {
        memcpy(seenNames[seenNameCount], nameBuf, 32);
        lastLocoObj[seenNameCount] = nullptr;
        return seenNameCount++;
    }
    return -1; // table pleine
}

// --- forward decl (defini avec le Hook 9, mais utilise ici) ---
typedef void* (*TrySpawnPlayerAtContinue_t)(void* retOut, int charIndex, void* continueData,
                                              void* locA, void* locB, void* checkpoint);
extern TrySpawnPlayerAtContinue_t originalTrySpawnPlayerAtContinue;
extern void* g_lastContinueData;
extern void* g_lastLocA;
extern void* g_lastLocB;
extern void* g_lastCheckpoint;
extern int g_lastCharIndex;
extern bool g_haveCapturedSpawnArgs;

// Flag arme par HotkeyThread (F10), consomme ici depuis HookedLocoUpdate.
// HookedLocoUpdate tourne sur un NdJobWorkerThread legitime (appele par le
// moteur lui-meme via le hook), contrairement a HotkeyThread qui est un
// thread Win32 brut (CreateThread) jamais enregistre dans ndjob. Appeler
// TrySpawnPlayerAtContinue directement depuis HotkeyThread crash en
// 0xc0000005 dans ndjob::SetJobLocalStorage (freeSlotIndex >= 0 assert)
// car ce thread n'a pas de job-local-storage configure. Le flag deplace
// l'appel reel vers un thread ou le moteur tourne deja legitimement.
static volatile LONG g_triggerSpawn2 = 0;

void* HookedLocoUpdate(void* locoObj, float deltaTime, void* ctx) {
    // Consommation prioritaire du trigger F10, avant tout le reste.
    // InterlockedCompareExchange(&g_triggerSpawn2, 0, 1) : si la valeur
    // actuelle est 1, on la remet a 0 et on entre dans le if. Si plusieurs
    // entites appellent HookedLocoUpdate dans la meme frame, seule la
    // premiere consomme le flag -> pas de double-spawn.
    if (InterlockedCompareExchange(&g_triggerSpawn2, 0, 1) == 1) {
        if (g_haveCapturedSpawnArgs && originalTrySpawnPlayerAtContinue) {
            printf("[SPAWN2] Trigger consomme depuis HookedLocoUpdate (job thread legitime), "
                   "charIndex=%d continueData=%p checkpoint=%p\n",
                   g_lastCharIndex, g_lastContinueData, g_lastCheckpoint);
            static char retBuf[64] = {};
            memset(retBuf, 0, sizeof(retBuf));
            void* result = originalTrySpawnPlayerAtContinue(
                retBuf, g_lastCharIndex, g_lastContinueData, g_lastLocA, g_lastLocB, g_lastCheckpoint);
            printf("[SPAWN2] termine, retOut=%p result=%p\n", (void*)retBuf, result);
            HexDump("SPAWN2 retOut", retBuf, 0x20);
        } else {
            printf("[SPAWN2] trigger consomme mais aucun param capture -- rien fait\n");
        }
    }

    if (locoObj) {
        locoFrameCounter++;

        void* parentObj = *(void**)((char*)locoObj + 0x008);
        char* nameBuf = (char*)parentObj + 0x050;

        if (locoFrameCounter <= 300) {
            bool isNew;
            int idx = FindOrAddName(nameBuf, &isNew);
            if (idx >= 0) lastLocoObj[idx] = locoObj;

            for (int i = 0; i < 16; i++) {
                if (candidates[i] == locoObj) { candidateCounts[i]++; break; }
                if (candidates[i] == nullptr) { candidates[i] = locoObj; candidateCounts[i] = 1; break; }
            }
            if (locoFrameCounter == 300) {
                int max1 = 0, max2 = 0;
                void* obj1 = nullptr, *obj2 = nullptr;
                for (int i = 0; i < 16; i++) {
                    if (candidateCounts[i] > max1) {
                        max2 = max1; obj2 = obj1;
                        max1 = candidateCounts[i]; obj1 = candidates[i];
                    } else if (candidateCounts[i] > max2) {
                        max2 = candidateCounts[i]; obj2 = candidates[i];
                    }
                }
                ellieObj = obj1;
                if (ellieObj) {
                    void* eParent = *(void**)((char*)ellieObj + 0x008);
                    printf("[ELLIE ARCHE-DUMP] parent=%p\n", eParent);
                    HexDump("ELLIE PARENT", eParent, 0x120);
                }
                companionObj = obj2;
                printf("[ELLIE] @ %p (%d appels)\n", ellieObj, max1);
                printf("[COMPANION] @ %p (%d appels)\n", companionObj, max2);
                if (companionObj) {
                    void* cParent = *(void**)((char*)companionObj + 0x008);
                    char cName[33] = {};
                    if (cParent) memcpy(cName, (char*)cParent + 0x050, 32);
                    printf("[COMPANION NOM] \"%s\"\n", cName);
                }
                printf("[CALIBRATION] %d noms distincts vus dans les 300 premieres frames\n", seenNameCount);
            }
        } else {
            bool isNew;
            int idx = FindOrAddName(nameBuf, &isNew);

            if (isNew) {
                char readableName[33] = {};
                memcpy(readableName, nameBuf, 32);
                printf("[NEW ENTITY] nom=\"%s\" parent=%p (frame %d)\n",
                       readableName, parentObj, locoFrameCounter);
                HexDump("NEW ENTITY PARENT", parentObj, 0x120);
                if (idx >= 0) lastLocoObj[idx] = locoObj;
            } else if (idx >= 0 && lastLocoObj[idx] != locoObj) {
                // Throttle par temps reel (meme raison que pour ELLIE POS):
                // locoFrameCounter est partage entre toutes les entites, donc un seuil
                // en "frames" ne correspond pas a un temps reel fixe. GetTickCount64()
                // garantit ~1 log toutes les 3s par perso, peu importe le nombre d'entites.
                static ULONGLONG lastLoggedTick[64] = {};
                ULONGLONG now = GetTickCount64();
                if (now - lastLoggedTick[idx] >= 3000) {
                    char readableName[33] = {};
                    memcpy(readableName, nameBuf, 32);
                    printf("[STATE CHANGE] \"%s\" nouveau locoObj=%p (frame %d)\n",
                           readableName, locoObj, locoFrameCounter);
                    lastLoggedTick[idx] = now;
                }
                lastLocoObj[idx] = locoObj;
            }
        }

        if (ellieObj && locoObj == ellieObj) {
            float x = *(float*)((char*)locoObj + 0x158);
            float y = *(float*)((char*)locoObj + 0x154);
            float z = *(float*)((char*)locoObj + 0x150);

            if (udpSocket != INVALID_SOCKET) {
                PosPacket pkt = { PKT_POS, x, y, z };
                sockaddr_in dest = {};
                dest.sin_family = AF_INET;
                dest.sin_port = htons(remotePort);
                dest.sin_addr.s_addr = inet_addr("127.0.0.1");
                sendto(udpSocket, (char*)&pkt, sizeof(pkt), 0, (sockaddr*)&dest, sizeof(dest));
            }

            // Throttle par temps reel: locoFrameCounter est incremente a CHAQUE appel
            // du hook, pour TOUTES les entites (pas juste Ellie). Avec 8 persos actifs
            // le modulo se declenche 8x plus souvent que prevu -> spam. On utilise
            // GetTickCount64() pour avoir un vrai throttle ~1x/seconde quel que soit
            // le nombre d'entites en jeu.
            static ULONGLONG lastEllieLogTick = 0;
            ULONGLONG now = GetTickCount64();
            if (now - lastEllieLogTick >= 1000) {
                printf("[ELLIE POS] X=%.3f Y=%.3f Z=%.3f\n", x, y, z);
                if (hasRemote)
                    printf("[REMOTE POS] X=%.3f Y=%.3f Z=%.3f\n", remoteX, remoteY, remoteZ);
                lastEllieLogTick = now;
            }
        }

        if (companionObj && locoObj == companionObj && hasRemote && myPort == INSTANCE_2_PORT) {
            *(float*)((char*)locoObj + 0x158) = remoteX;
            *(float*)((char*)locoObj + 0x154) = remoteY;
            *(float*)((char*)locoObj + 0x150) = remoteZ;
        }
    }
    return originalLocoUpdate(locoObj, deltaTime, ctx);
}

// ============================================================
// Hook 3 — SchemaRespawner::SpawnNpc
// ============================================================
typedef void (*SpawnNpc_t)(void* thisPtr);
SpawnNpc_t originalSpawnNpc = nullptr;
static void* schemaRespawnerObj = nullptr;

void HookedSpawnNpc(void* thisPtr) {
    if (schemaRespawnerObj == nullptr) {
        schemaRespawnerObj = thisPtr;
        printf("[SPAWN] SchemaRespawner capture @ %p\n", thisPtr);
    }
    printf("[SPAWN] SpawnNpc appele, this=%p\n", thisPtr);
    HexDump("SPAWN", thisPtr, 0x120);
    originalSpawnNpc(thisPtr);
}

// ============================================================
// Hook 4 — InitRespawner pour capturer le this
// ============================================================
typedef void* (*InitRespawner_t)(void* thisPtr);
InitRespawner_t originalInitRespawner = nullptr;
static void* capturedRespawner = nullptr;

void* HookedInitRespawner(void* thisPtr) {
    capturedRespawner = thisPtr;
    printf("[RESPAWNER] this capture @ %p\n", thisPtr);
    HexDump("RESPAWNER", thisPtr, 0x120);
    return originalInitRespawner(thisPtr);
}

// ============================================================
// Hook 5 — RECON SendNetEventNpcSpawn (passif, dump-only)
// void __cdecl SendNetEventNpcSpawn(const ProcessSpawnInfo&, const NpcSpawnInfo&, Npc*)
// ============================================================
typedef void (*SendNetEventNpcSpawn_t)(void* processSpawnInfo, void* npcSpawnInfo, void* npc);
SendNetEventNpcSpawn_t originalSendNpcSpawn = nullptr;
static int spawnReconCount = 0;

void HookedSendNpcSpawn(void* processSpawnInfo, void* npcSpawnInfo, void* npc) {
    int n = ++spawnReconCount;
    if (n <= RECON_DUMP_LIMIT) {
        printf("\n[RECON-SPAWN #%d] ===== SendNetEventNpcSpawn =====\n", n);
        printf("[RECON-SPAWN] Npc* = %p\n", npc);
        HexDump("ProcessSpawnInfo", processSpawnInfo, 0x80);
        HexDump("NpcSpawnInfo", npcSpawnInfo, 0x80);
        if (npc) HexDump("Npc spawne", npc, 0xC0);
    } else if (n == RECON_DUMP_LIMIT + 1) {
        printf("[RECON-SPAWN] limite de dump atteinte -- silence total desormais\n");
    }
    originalSendNpcSpawn(processSpawnInfo, npcSpawnInfo, npc);
}

// ============================================================
// Hook 6 — RECON NetEventNpcSpawn::Execute (passif, dump-only)
// ============================================================
typedef void* (*NpcSpawnExecute_t)(void* netEvent);
NpcSpawnExecute_t originalNpcSpawnExecute = nullptr;
static int execReconCount = 0;

void* HookedNpcSpawnExecute(void* netEvent) {
    int n = ++execReconCount;
    if (n <= RECON_DUMP_LIMIT) {
        printf("\n[RECON-EXEC #%d] ===== NetEventNpcSpawn::Execute =====\n", n);
        HexDump("NetEvent recu", netEvent, 0x100);
    } else if (n == RECON_DUMP_LIMIT + 1) {
        printf("[RECON-EXEC] limite de dump atteinte -- silence total desormais\n");
    }
    return originalNpcSpawnExecute(netEvent);
}

// ============================================================
// Hook 7 — RECON Process::SpawnProcess (passif, dump-only)
// class Process* __cdecl Process::SpawnProcess(const ProcessSpawnInfo&, Err*)
// rcx = ProcessSpawnInfo*, rdx = Err* (out), retour rax = Process*
// C'est la route GENERIQUE empruntee par TOUS les process du jeu (Player,
// Npc, infectes, objets), solo inclus -- contrairement aux hooks NetEvent
// au-dessus qui ne se declenchent qu'en multijoueur.
// ============================================================
typedef void* (*SpawnProcess_t)(void* processSpawnInfo, void* errOut);
SpawnProcess_t originalSpawnProcess = nullptr;
static int spawnProcessReconCount = 0;

// ============================================================
// BASCULE D'ARCHETYPE (bait-and-switch)
// On mute le hash StringId64 a +0x08 du ProcessSpawnInfo AVANT l'appel
// original. Contrairement a une mutation dans Npc::Init (trop tard: la
// vtable de l'objet est deja figee a l'allocation), muter ici garantit
// que le moteur choisit directement la bonne vtable (Dina) des le depart.
//
// ACTIVATION: mettre ENABLE_ARCHETYPE_SWAP a 1 pour activer.
// Hash source = generic Infected (runner/clicker supermarche, confirme
// identique sur 6 instances). Hash cible = Dina (confirme via Npc::Init
// recon). Swap UNIQUEMENT si le hash matche exactement la source, pour
// ne jamais toucher aux milliers d'autres spawns (vfx, sons, items...).
// ============================================================
#define ENABLE_ARCHETYPE_SWAP 0   // <-- desactive, piste abandonnee (mismatch m_pRecord), on vise TrySpawnPlayerAtContinue maintenant

static const uint64_t HASH_SRC_INFECTED_GENERIC = 0x9AC5FBA6AD7337B9ULL; // B9 37 73 AD A6 FB C5 9A (LE)
static const uint64_t HASH_DST_DINA              = 0xF46F927358AB6273ULL; // 73 62 AB 58 73 92 6F F4 (LE)

void* HookedSpawnProcess(void* processSpawnInfo, void* errOut) {
    int n = ++spawnProcessReconCount;
    bool doDump = n <= RECON_DUMP_LIMIT;
    if (doDump) {
        printf("\n[RECON-SPAWNPROC #%d] ===== Process::SpawnProcess =====\n", n);
        HexDump("ProcessSpawnInfo", processSpawnInfo, 0xC0);
    } else if (n == RECON_DUMP_LIMIT + 1) {
        printf("[RECON-SPAWNPROC] limite de dump atteinte -- silence total desormais"
               " (cette fonction tourne des milliers de fois/minute, voir Npc::Init pour le reste)\n");
    }
    // Volontairement AUCUN printf au-dela de la limite: SpawnProcess est appele
    // pour tout (vfx, sons, items...) des milliers de fois par minute, et un
    // printf par appel bloquait le thread de jeu (cf. session de lag precedente).

#if ENABLE_ARCHETYPE_SWAP
    if (processSpawnInfo) {
        uint64_t* hashSlot = (uint64_t*)((char*)processSpawnInfo + 0x08);
        if (*hashSlot == HASH_SRC_INFECTED_GENERIC) {
            printf("[SWAP] Archetype Infected generique detecte @ %p -> bascule vers Dina\n", processSpawnInfo);
            *hashSlot = HASH_DST_DINA;
        }
    }
#endif

    void* result = originalSpawnProcess(processSpawnInfo, errOut);

    if (doDump) {
        printf("[RECON-SPAWNPROC #%d] Process* retourne = %p\n", n, result);
        if (result) HexDump("Process cree", result, 0x80);
    }
    return result;
}

// ============================================================
// Hook 8 — RECON Npc::Init (passif, dump-only)
// rcx = this (le Npc fraichement alloue) -> stocke en r14 dans la fonction
// rdx = arg2 (role exact a confirmer par le dump -- possiblement le
//       ProcessSpawnInfo, ou un wrapper autour)
// r8  = arg3 -> stocke en r15, utilise comme objet avec vtable
//       (call qword ptr [rax+80] etc.) -- probablement un contexte/iterateur
//       de construction (NdScriptArgIterator ou equivalent), PAS juste
//       le ProcessSpawnInfo comme la signature C++ le laissait penser.
// Le gros interet ici: "this" est l'objet Npc EN COURS de construction,
// donc on peut voir sa memoire juste avant qu'il devienne pleinement
// fonctionnel -- utile pour comprendre le layout sans heuristique de
// comptage de frames comme pour ellieObj/companionObj.
// ============================================================
typedef intptr_t (*NpcInit_t)(void* thisNpc, void* arg2, void* arg3);
NpcInit_t originalNpcInit = nullptr;
static int npcInitReconCount = 0;

// Dump par NOM DISTINCT plutot que par les N premiers appels bruts:
// les runners du supermarche spawnent en rafale au debut et epuisaient
// la limite avant qu'on voie un autre type (Dina, etc.). Ici on garde
// une table des noms deja vus (8 premiers caracteres suffisent a
// distinguer "npc-pat..." de "dina" etc.) et on dump uniquement les
// types JAMAIS vus, jusqu'a MAX_DISTINCT_NAMES types differents.
#define MAX_DISTINCT_NAMES 10
static char seenNpcInitNames[MAX_DISTINCT_NAMES][32] = {};
static int seenNpcInitNameCount = 0;

intptr_t HookedNpcInit(void* thisNpc, void* arg2, void* arg3) {
    int n = ++npcInitReconCount;

    // this+0x50 contient le nom tronque a 32 bytes (voir dumps precedents)
    const char* name = thisNpc ? (const char*)((char*)thisNpc + 0x50) : nullptr;

    bool isNewName = false;
    if (name && seenNpcInitNameCount < MAX_DISTINCT_NAMES) {
        isNewName = true;
        for (int i = 0; i < seenNpcInitNameCount; i++) {
            if (memcmp(seenNpcInitNames[i], name, 32) == 0) { isNewName = false; break; }
        }
        if (isNewName) {
            memcpy(seenNpcInitNames[seenNpcInitNameCount], name, 32);
            seenNpcInitNameCount++;
        }
    }

    if (isNewName) {
        char readableName[33] = {};
        if (name) memcpy(readableName, name, 32);
        printf("\n[RECON-NPCINIT #%d] ===== Npc::Init (NOUVEAU TYPE: \"%s\") ===== this=%p arg2=%p arg3=%p\n",
               n, readableName, thisNpc, arg2, arg3);
        HexDump("Npc (this) AVANT Init", thisNpc, 0x120);
        if (arg2) HexDump("arg2 (rdx) = NpcSpawnInfo", arg2, 0xC0);
        if (arg3) HexDump("arg3 (r8) = ProcessSpawnInfo", arg3, 0x80);
        if (seenNpcInitNameCount == MAX_DISTINCT_NAMES) {
            printf("[RECON-NPCINIT] %d types distincts captures, silence total desormais\n", MAX_DISTINCT_NAMES);
        }
    }
    return originalNpcInit(thisNpc, arg2, arg3);
}

// ============================================================
// Hook 9 — RECON TrySpawnPlayerAtContinue (passif, dump-only)
// TypedProcessHandle<Process>* __cdecl TrySpawnPlayerAtContinue(
//     TypedProcessHandle<Process>* retOut /* rcx, retour cache */,
//     int charIndex                       /* rdx */,
//     const DC::Continue* continueData    /* r8 */,
//     const Locator* locA                 /* r9 */,
//     const Locator* locB                 /* pile */,
//     const GameSave::PlayerCheckpoint* checkpoint /* pile */
// )
// C'est LE point d'entree natif qui spawn le joueur (Ellie) a un checkpoint.
// Throttle global (pas de filtre par nom ici, cette fonction est rare —
// appelee au chargement/checkpoint, pas a chaque frame).
// ============================================================
TrySpawnPlayerAtContinue_t originalTrySpawnPlayerAtContinue = nullptr;
static int trySpawnPlayerReconCount = 0;

// Capture des derniers params valides vus, pour rappel manuel via F10 (test
// "est-ce qu'on peut spawn un 2e Player avec les memes donnees ?").
// ATTENTION: continueData/checkpoint pointent vers de la memoire (souvent
// sur la pile du thread de jeu au moment du spawn) qui peut etre invalidee
// apres coup -- le trigger F10 doit etre presse PEU DE TEMPS apres le
// declenchement naturel pour avoir une chance que ce soit encore valide.
// Si la memoire a ete reutilisee/liberee, attends-toi a un comportement
// absurde silencieux (pas forcement un crash). Si ca devient un probleme,
// faire un deep-copy (memcpy) de ces buffers ICI, au moment de la capture,
// plutot que de garder de simples pointeurs vers la pile du jeu.
void* g_lastContinueData = nullptr;
void* g_lastLocA = nullptr;
void* g_lastLocB = nullptr;
void* g_lastCheckpoint = nullptr;
int g_lastCharIndex = 0;
bool g_haveCapturedSpawnArgs = false;

// Buffers statiques pour deep-copy de continueData/checkpoint. Necessaire car
// checkpoint pointe vers la pile du thread de jeu (confirme: range d'adresse
// 0x1c78bfcd40, identique aux autres ProcessSpawnInfo/NpcSpawnInfo sur pile
// vus dans le meme run) -- reutilisee/invalidee en quelques frames. Garder
// un simple pointeur brut (g_lastCheckpoint = checkpoint) ne survit pas au
// temps de reaction humain sur F10. continueData lui est en heap (range
// 0x91...) et serait probablement safe en pointeur brut, mais on le copie
// aussi par coherence/simplicite -- le cout est negligeable (0x100 bytes).
// Taille 0x100: les HexDump montrent des structs de 0x80 (128) bytes, on
// prend une marge de securite x2 au cas ou le vrai sizeof deborde ce qu'on
// a affiche. Pas de risque si ca lit de la memoire adjacente valide, juste
// du bruit en plus dans le buffer.
static char g_continueDataBuf[0x100] = {};
static char g_checkpointBuf[0x100] = {};

void* HookedTrySpawnPlayerAtContinue(void* retOut, int charIndex, void* continueData,
                                       void* locA, void* locB, void* checkpoint) {
    int n = ++trySpawnPlayerReconCount;
    printf("\n[RECON-TRYSPAWNPLAYER #%d] ===== TrySpawnPlayerAtContinue =====\n", n);
    printf("[RECON-TRYSPAWNPLAYER] charIndex=%d continueData=%p locA=%p locB=%p checkpoint=%p\n",
           charIndex, continueData, locA, locB, checkpoint);
    if (n <= RECON_DUMP_LIMIT) {
        if (continueData) HexDump("DC::Continue", continueData, 0x80);
        if (locA) HexDump("Locator A", locA, 0x40);
        if (locB) HexDump("Locator B", locB, 0x40);
        if (checkpoint) HexDump("PlayerCheckpoint", checkpoint, 0x80);
    }

    // Deep-copy AVANT l'appel original: continueData/checkpoint pourraient
    // theoriquement etre modifies/liberes par l'appel lui-meme (peu probable
    // ici vu qu'ils sont en lecture pour le moteur, mais copier avant plutot
    // qu'apres coute rien et elimine ce risque par construction).
    if (continueData) memcpy(g_continueDataBuf, continueData, sizeof(g_continueDataBuf));
    if (checkpoint)   memcpy(g_checkpointBuf, checkpoint, sizeof(g_checkpointBuf));

    g_lastContinueData = continueData ? g_continueDataBuf : nullptr;
    g_lastLocA = locA;   // null dans tous les calls naturels observes -> pas de copie
    g_lastLocB = locB;
    g_lastCheckpoint = checkpoint ? g_checkpointBuf : nullptr;
    g_lastCharIndex = charIndex;
    g_haveCapturedSpawnArgs = true;
    printf("[RECON-TRYSPAWNPLAYER] params copies (deep-copy) pour rappel manuel -> F10 pour armer le trigger\n");

    void* result = originalTrySpawnPlayerAtContinue(retOut, charIndex, continueData, locA, locB, checkpoint);
    printf("[RECON-TRYSPAWNPLAYER #%d] retour @ %p\n", n, retOut);
    if (n <= RECON_DUMP_LIMIT && retOut) HexDump("TypedProcessHandle retourne", retOut, 0x20);
    return result;
}

// ============================================================
// UDP
// ============================================================
DWORD WINAPI UDPReceiveThread(LPVOID) {
    PosPacket pkt;
    sockaddr_in src = {};
    int srcLen = sizeof(src);
    while (true) {
        int r = recvfrom(udpSocket, (char*)&pkt, sizeof(pkt), 0, (sockaddr*)&src, &srcLen);
        if (r == sizeof(PosPacket)) {
            if (pkt.type == PKT_POS) {
                remoteX = pkt.x; remoteY = pkt.y; remoteZ = pkt.z;
                hasRemote = true;
            } else if (pkt.type == PKT_SPAWN_TRIGGER) {
                if (g_haveCapturedSpawnArgs) {
                    InterlockedExchange(&g_triggerSpawn2, 1);
                    printf("[SPAWN2] Trigger distant recu (F10 sur l'autre instance) -> arme localement\n");
                } else {
                    printf("[SPAWN2] Trigger distant recu mais aucun param capture localement -- ignore\n");
                }
            }
        }
    }
    return 0;
}

void InitUDP() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(INSTANCE_1_PORT);

    if (bind(udpSocket, (sockaddr*)&addr, sizeof(addr)) == 0) {
        myPort = INSTANCE_1_PORT;
        remotePort = INSTANCE_2_PORT;
        printf("[UDP] Instance 1 - port %d\n", myPort);
    } else {
        addr.sin_port = htons(INSTANCE_2_PORT);
        bind(udpSocket, (sockaddr*)&addr, sizeof(addr));
        myPort = INSTANCE_2_PORT;
        remotePort = INSTANCE_1_PORT;
        printf("[UDP] Instance 2 - port %d\n", myPort);
    }
    CreateThread(nullptr, 0, UDPReceiveThread, nullptr, 0, nullptr);
}

// ============================================================
// F9  — rejoue manuellement SpawnNpc sur le respawner capture
// F10 — ARME le trigger de spawn manuel (g_triggerSpawn2). L'appel reel a
//        TrySpawnPlayerAtContinue ne se fait PLUS ici (thread Win32 brut,
//        pas enregistre dans ndjob -> crash 0xc0000005 / freeSlotIndex
//        assert) mais est consomme depuis HookedLocoUpdate, qui tourne
//        sur un NdJobWorkerThread legitime puisqu'appele par le moteur.
// ============================================================
DWORD WINAPI HotkeyThread(LPVOID) {
    while (true) {
        if (GetAsyncKeyState(VK_F9) & 1) {
            if (capturedRespawner && originalSpawnNpc) {
                printf("[SPAWN] F9 -> appel manuel SpawnNpc, this=%p\n", capturedRespawner);
                originalSpawnNpc(capturedRespawner);
                printf("[SPAWN] F9 -> done\n");
            } else {
                printf("[SPAWN] F9 -> capturedRespawner encore null, rien a appeler\n");
            }
        }
        if (GetAsyncKeyState(VK_F10) & 1) {
            if (g_haveCapturedSpawnArgs) {
                InterlockedExchange(&g_triggerSpawn2, 1);
                printf("[SPAWN2] F10 -> trigger arme, consommation au prochain HookedLocoUpdate (~16ms)\n");
            } else {
                printf("[SPAWN2] F10 -> aucun param capture pour l'instant (attends qu'un spawn naturel passe dans le recon)\n");
            }
            if (udpSocket != INVALID_SOCKET) {
                PosPacket trigger = { PKT_SPAWN_TRIGGER, 0, 0, 0 };
                sockaddr_in dest = {};
                dest.sin_family = AF_INET;
                dest.sin_port = htons(remotePort);
                dest.sin_addr.s_addr = inet_addr("127.0.0.1");
                sendto(udpSocket, (char*)&trigger, sizeof(trigger), 0, (sockaddr*)&dest, sizeof(dest));
                printf("[SPAWN2] Trigger envoye a l'instance distante (port %d)\n", remotePort);
            }
        }
        Sleep(50);
    }
    return 0;
}

// ============================================================
// Helper
// ============================================================
static void InstallHook(void* target, void* detour, void** original, const char* name) {
    MH_STATUS status = MH_CreateHook(target, detour, original);
    if (status == MH_OK) {
        MH_EnableHook(target);
        printf("[+] Hook %s actif @ %p\n", name, target);
    } else {
        printf("[-] Hook %s FAIL - %s\n", name, MH_StatusToString(status));
    }
}

// Hook avec patch de protection memoire (necessaire pour certaines fonctions)
static void InstallHookProtected(void* target, void* detour, void** original, const char* name) {
    DWORD oldProtect;
    VirtualProtect(target, 32, PAGE_EXECUTE_READWRITE, &oldProtect);
    InstallHook(target, detour, original, name);
    VirtualProtect(target, 32, PAGE_EXECUTE_READ, &oldProtect);
}

// ============================================================
// InitHooks
// ============================================================
void InitHooks() {
    printf("[TLOU2] Installation des hooks...\n");
    MH_Initialize();

    HMODULE base = GetModuleHandleA("tlou-ii.exe");
    if (!base) { printf("[-] base null\n"); return; }
    printf("[*] Base: %p\n", base);

    InstallHook((char*)base + OFF_NETEVENT_CHARMOVE_EXEC, (void*)&HookedExecute,
                (void**)&originalExecute, "NetEventCharacterMove::Execute");

    InstallHook((char*)base + OFF_LOCOMOTION_UPDATE, (void*)&HookedLocoUpdate,
                (void**)&originalLocoUpdate, "CharacterMotionMatchLocomotion::Update");

    InstallHookProtected((char*)base + OFF_SCHEMA_RESPAWNER_SPAWN, (void*)&HookedSpawnNpc,
                         (void**)&originalSpawnNpc, "SchemaRespawner::SpawnNpc");

    InstallHook((char*)base + OFF_INIT_RESPAWNER, (void*)&HookedInitRespawner,
                (void**)&originalInitRespawner, "InitRespawner");

    // --- Hooks RECON (passifs) ---
    if (OFF_SEND_NETEVENT_NPCSPAWN != 0) {
        InstallHook((char*)base + OFF_SEND_NETEVENT_NPCSPAWN, (void*)&HookedSendNpcSpawn,
                    (void**)&originalSendNpcSpawn, "SendNetEventNpcSpawn [RECON]");
    } else {
        printf("[!] OFF_SEND_NETEVENT_NPCSPAWN non renseigne, hook recon ignore\n");
    }

    if (OFF_NETEVENT_NPCSPAWN_EXECUTE != 0) {
        InstallHook((char*)base + OFF_NETEVENT_NPCSPAWN_EXECUTE, (void*)&HookedNpcSpawnExecute,
                    (void**)&originalNpcSpawnExecute, "NetEventNpcSpawn::Execute [RECON]");
    } else {
        printf("[!] OFF_NETEVENT_NPCSPAWN_EXECUTE non renseigne, hook recon ignore\n");
    }

    if (OFF_PROCESS_SPAWNPROCESS != 0) {
        InstallHook((char*)base + OFF_PROCESS_SPAWNPROCESS, (void*)&HookedSpawnProcess,
                    (void**)&originalSpawnProcess, "Process::SpawnProcess [RECON-SOLO]");
    } else {
        printf("[!] OFF_PROCESS_SPAWNPROCESS non renseigne, hook recon ignore\n");
    }

    if (OFF_NPC_INIT != 0) {
        InstallHook((char*)base + OFF_NPC_INIT, (void*)&HookedNpcInit,
                    (void**)&originalNpcInit, "Npc::Init [RECON-SOLO]");
    } else {
        printf("[!] OFF_NPC_INIT non renseigne, hook recon ignore\n");
    }

    if (OFF_TRYSPAWN_PLAYER_AT_CONTINUE != 0) {
        InstallHook((char*)base + OFF_TRYSPAWN_PLAYER_AT_CONTINUE, (void*)&HookedTrySpawnPlayerAtContinue,
                    (void**)&originalTrySpawnPlayerAtContinue, "TrySpawnPlayerAtContinue [RECON-SOLO]");
    } else {
        printf("[!] OFF_TRYSPAWN_PLAYER_AT_CONTINUE non renseigne, hook recon ignore\n");
    }

    printf("[*] Hooks actifs\n");
    printf("[*] F9 disponible si capturedRespawner non-null\n");
    printf("[*] F10 arme le spawn manuel (consomme depuis HookedLocoUpdate)\n");
    printf("[*] Recon spawn en attente d'un encounter naturel (pas de dev menu dispo)\n");
    InitUDP();
    CreateThread(nullptr, 0, HotkeyThread, nullptr, 0, nullptr);
}

// ============================================================
// InjectIntoTLOU2
// ============================================================
void InjectIntoTLOU2() {
    DWORD targetPid = 0;
    while (!targetPid) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(snap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, "tlou-ii.exe") == 0) {
                    targetPid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
        if (!targetPid) { printf("[*] retry...\n"); Sleep(2000); }
    }
    printf("[*] tlou-ii.exe PID=%lu\n", targetPid);

    char dllPath[MAX_PATH];
    GetModuleFileNameA(GetModuleHandleA("tlou2_hook.asi"), dllPath, MAX_PATH);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProc) { printf("[-] OpenProcess failed\n"); return; }

    void* remoteMem = VirtualAllocEx(hProc, nullptr, strlen(dllPath) + 1,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProc, remoteMem, dllPath, strlen(dllPath) + 1, nullptr);

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "LoadLibraryA"),
        remoteMem, 0, nullptr);

    if (hThread) {
        WaitForSingleObject(hThread, 10000);
        printf("[+] DLL injectee\n");
        CloseHandle(hThread);
    } else {
        printf("[-] Injection failed: %lu\n", GetLastError());
    }

    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProc);
}

// ============================================================
// Init
// ============================================================
void Init() {
    Sleep(3000);
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    // Fix: GetModuleBaseNameA avec hModule=nullptr est non fiable.
    // GetModuleFileNameA(nullptr, ...) recupere toujours le module courant.
    char procPath[MAX_PATH];
    GetModuleFileNameA(nullptr, procPath, MAX_PATH);
    const char* procName = strrchr(procPath, '\\');
    procName = procName ? procName + 1 : procPath;

    printf("[INIT] Process: %s\n", procName);

    if (_stricmp(procName, "tlou-ii.exe") == 0) {
        InitHooks();
        return;
    }

    printf("[INIT] crs-video.exe, injection...\n");
    InjectIntoTLOU2();
}

// ============================================================
// DllMain
// ============================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Init, nullptr, 0, nullptr);
    }
    return TRUE;
}