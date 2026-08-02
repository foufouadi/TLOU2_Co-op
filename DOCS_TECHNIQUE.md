# Technical documentation: reverse engineering TLOU2 PC

This document collects everything found so far about the tlou-ii.exe binary (The Last of Us Part II Remastered, PC): addresses, offsets, memory structures, and paths that were tried and abandoned. The goal is to let someone else pick up the project without starting from zero.

All offsets are relative to the tlou-ii.exe module base as loaded in memory (retrieved via GetModuleHandleA("tlou-ii.exe")), not to the static address shown in IDA. To convert a static IDA address back to an offset: offset = static_address minus static_image_base (Edit > Segments in IDA gives the static image base).

## 1. Infrastructure

### The game runs as two processes

tlou-ii.exe, the actual engine and gameplay process, is launched as a subprocess of crs-video.exe, which is probably a launcher or video wrapper. A DLL injected into crs-video.exe never sees the game's own code, so the DLL has to specifically get itself into tlou-ii.exe.

The approach used here: the DLL, once loaded into whichever process picked it up, checks its own process name with GetModuleFileNameA(nullptr, ...). If it is running inside crs-video.exe, it waits for tlou-ii.exe to appear (polling with CreateToolhelp32Snapshot), then injects itself using CreateRemoteThread plus a remote call to LoadLibraryA. If it is already inside tlou-ii.exe, it installs the hooks directly.

One gotcha along the way: GetModuleBaseNameA(nullptr, ...) is unreliable for getting the current process name, GetModuleFileNameA(nullptr, ...) works correctly instead.

### Instance detection (1 vs 2)

There is no dedicated mechanism for this. Each instance tries to bind a UDP socket on port 9001. If that fails because the other instance already holds the port, it binds port 9002 instead. Whichever instance starts first becomes instance 1.

### Tools

ndmodloader loads .asi files (renamed DLLs) into the game process and enables Naughty Dog's native dev menu.

dconstruct disassembles the DC (Decima/Racket) scripts packed inside bin.psarc, 8005 files extracted in total.

ndarc decompresses the game's .psarc archives.

x64dbg is used for live debugging of tlou-ii.exe, setting breakpoints, and scanning memory for strings.

IDA is used for static disassembly, offset calculation, and cross references.

MinHook is the hooking library (C, x86/x64) used to intercept engine function calls, compiled from source inside the project.

### Naughty Dog dev menu

Reachable with Ctrl+~ once ndmodloader is installed. Useful entries include Player Menu, Debug in Final, Print Player State, which shows Ellie's full state in real time, Player Menu, Target Visibility, Show Visible NPC Targets, and a Net menu which is empty in solo play but confirms the networking code is present in the build.

## 2. Confirmed offsets (used in dllmain.cpp)

Example module base observed: 00007FF7580E0000. This varies between patches and due to ASLR, always recompute it from GetModuleHandleA at runtime rather than hardcoding it.

| Function | Offset | Role |
|---|---|---|
| NetEventCharacterMove::Execute | 0x3DBE90 | Applies a received network movement update on the client |
| CharacterMotionMatchLocomotion::Update | 0x1F7ACA0 | Runs every frame for every entity, player, companion, and NPCs alike. This is the main hook point currently used |
| SchemaRespawner::SpawnNpc | 0x442B80 | NPC spawn function, abandoned lead, see section 4 |
| InitRespawner | 0x4423C0 | Initializes the SchemaRespawner, abandoned lead |
| Process::SpawnProcess(const ProcessSpawnInfo&, Err*) | 0x14C9BB0 | Generic spawn route used by every process in the game (player, NPC, VFX, sounds, items), including in solo play |
| Npc::Init(const ProcessSpawnInfo&) | 0x4FB510 | Constructor and init for a freshly allocated Npc. It actually takes 3 parameters (rcx, rdx, r8), not 2 as the C++ signature suggests |
| TrySpawnPlayerAtContinue(...) | 0xDC1440 | The native entry point that spawns the player (Ellie) at a checkpoint. Current best lead for spawning a second player |

Offsets for the Factions networking route, dead code in solo play, never triggers outside multiplayer:

| Function | Offset | Note |
|---|---|---|
| NetEventNpcSpawn::Execute | 0x9ED4F0 | Confirmed by prologue (mov [rsp+18],rbx, push rbp,rdi,r14, sub rsp,400, preceded by int3 padding) |
| SendNetEventNpcSpawn(...) | 0x9EF4F0 | Confirmed by a similar prologue |

### Extended reference table (not hooked in the current code, useful for further work)

Found while exploring the networking system in IDA, static addresses, convert to an offset before use.

| Function | Static address | Purpose |
|---|---|---|
| NetEventNpcSpawn::Execute | 7FF6D847D7A0 | Client side reception of a networked NPC spawn |
| SendNetEventNpcSpawn(ProcessSpawnInfo&, NpcSpawnInfo&, Npc*) | 7FF6D847D8B0 | Sends a spawn, a candidate for forging a remote spawn |
| SendNetEventSyncNpcSpawn(EntitySpawner*, NpcSpawnInfo&, Npc*, int) | 7FF6D847D990 | Late join sync, for reconnect handling |
| CreateNetEventByType | 7FF6D8461F78 | Central NetEvent factory, useful for understanding the vtable layout |
| EventConnection::AddEvent(NetEvent*, uint, ushort*, bool) | 7FF6D8683C90 | Low level injection point into the network event queue |
| NetGameManager::SendNetEventMask | 7FF6D8463F08 | Dispatches events to trackers |
| SendNetEventCharacterMove(Npc*, ...) | 7FF6D847B800 | The NPC variant, different from the Player* variant at 7FF6D847B7A0 |
| NetEventRespawnPlayer::Fill / HostFill | 7FF6D847E3F0 | A host/client pattern that is already present in the binary |
| SendNetEventSetPlayerSpawnGroup(NetPlayerTracker*, StringId64) | 7FF6D8461AB0 | Spawn group management per player |

Other networking functions spotted, the full NetEventCharacterMove pipeline:

SendCharacterMoveUpdatesJob is the asynchronous job that sends the updates. NetGameManager::KickSendCharacterMoveUpdates triggers the send. NetEventCharacterMove::Fill and its NPC overload NetEventCharacterMove::Fill(const Npc*, bool) fill the packet for the player and NPC cases respectively. NetEventCharacterMove::FillAnimCmdBitStream encodes animation commands into a bitstream. NetEventCharacterMove::Write serializes the packet.

Original source file path recovered from an in-memory string: c:\branches\discbot03\t2r-pc-1.0.0\t2r\src\game\net\net-event\net-event-character-move.cpp

Wider SendNetEvent system, not explored in depth: SendNetEventSyncPlayers(uint) iterates over up to 7 players. SendNetEventSyncRespawns(int) and SendNetEventSyncOddLives handle respawns and extra lives. SendNetEventCoopTeamFailed(char) confirms a co-op mode existed internally. SendNetEventLateJoinStartGame confirms late join co-op support existed as well. SendNetEventSimpleSnapshot sends a basic snapshot. SendNetEventAttackExplosion, SendNetEventAttackMelee, and SendNetEventAttackProjectile sync attacks. SendNetEventSyncCarryObjects syncs carried objects.

Network monitoring strings, useful as search anchors when navigating the binary: "Player %s, Sent: %.3f", "Player %s, Received: %.3f", "Npc %s, Sent: %.3f", "Npc %s, Received: %.3f".

A full Factions session and matchmaking system is present in the binary and has not been explored in detail: TCP Session, NetMatchmakingRoomCreate/Join/Leave/Destroy, NetMatchmakingMemberJoined/Left, NetMatchmakingOwnerChanged, Create ND Session. NetCharacterSnapshot is 0x2290 bytes (8848 bytes), and NetCharacterCollision::Update handles networked collisions.

Other NetCharacter functions spotted: SetWeapons(NetWeaponSnapshot), SetGrenadeInHand(uint, uint), HandleTriggeredEffect, PostAnimUpdate_Async, NetMove::EventHandler, SetInTaunt.

## 3. Memory structures identified

### Locomotion object (CharacterMotionMatchLocomotion, pointer locoObj)

Offset 0x008 holds a pointer to the parent object, a wrapper that gets reallocated frequently, see the abandoned lead in section 4 about why this made deduplication unreliable. Offset 0xE0 holds the ActionState as an int. Offset 0x150 holds the Z position (forward/backward) as a float, offset 0x154 holds the Y position (height), and offset 0x158 holds the X position (left/right).

Calibration values observed in game: Z between -120 and -124 while moving forward, Y at 0.327 on the ground versus 0.606 at the top of a staircase, X between 203 and 197 while moving right.

The method used to find these offsets was a memory diff before and after a known movement, for example walking forward, then looking for floats that changed consistently with that movement.

Ellie is identified among all entities in the scene by counting calls during the first 300 frames after a level loads. Ellie is the locomotion object updated most often, for example 64 calls versus about 61 for the most active companion. The object with the highest call count is Ellie, the second highest is the companion.

### Parent object (parentObj = *(locoObj + 0x008)), generic entity object

Offset 0x000 holds the vtable pointer, which differs by the object's real type (for example D83A84B8 for an Infected, D85068F0 for a Player). Comparing against a known value lets you identify the type without knowing the full vtable layout ahead of time.

Offset 0x008 holds a short value that looks like a type id or hash, differing per instance.

Offset 0x030 holds a constant value of 01 00 01 00, likely a flag or set of flags.

Offset 0x038 holds a pointer to a string such as "Player" or "Infected", a readable class name that is useful for identifying an entity's type without the vtable.

Offset 0x048 holds the StringId64 hash of the entity's type or template, for example the generic "Infected" type. This value is identical across multiple instances of the same type and is copied in from the spawn context.

Offset 0x050 holds the entity's name in plain text, a 32 byte buffer, for example "npc-clicker-pharmacy-2". This is the most stable field for deduplicating or identifying an entity, it stays stable even when the surrounding memory wrappers get reallocated.

Offset 0x070 holds FF FF FF FF FF FF FF FF, a constant that is probably an "unassigned" id marker.

Offset 0x0D8 holds a pointer that is identical across every instance observed, for example 8E5D80D8. This is probably a shared singleton, such as the ProcessMgr or an allocator, not specific to any entity, and should be treated as noise.

It was confirmed that every NPC within the same group, for example three runners in a supermarket encounter, shares an identical memory layout, only the name at offset 0x050 differs.

### Spawn context (ProcessSpawnInfo / NpcSpawnInfo, captured through the recon hooks)

At arg2 + 0xB0 there is a pointer to the spawner's full, untruncated name (for example "npc-pat-supermarket-runner-1"), different from the 32 byte truncated name at this+0x50. This one comes from the original EntitySpawner placed in the level by the developers, not from the Npc instance itself.

At arg3 + 0x08 there is a constant StringId64 (for example B9 37 73 AD A6 FB C5 9A in little endian) that is identical across multiple NPCs of the same generic type. The same hash is also copied into this+0x48 on the final Npc object.

A shared manager pointer (for example 00 00 C0 4E 91 00 00 00) was found inside ProcessSpawnInfo, inside arg3, and in several other dumps. It is a global singleton, likely ProcessMgr or the process allocator. It should be ignored, it is not specific to any single spawn.

### PlayerCheckpoint (captured through TrySpawnPlayerAtContinue)

Structure decoded as floats from a real memory dump. Offset 0x10 decoded to -529.4 and corresponds to the Z position. Offset 0x14 decoded to 20.55 and corresponds to the Y position. Offset 0x18 decoded to 271.97 and corresponds to the X position. Offset 0x1C decoded to 71.4, its exact role is unconfirmed. Offsets 0x20 through 0x2C hold 4 floats, likely a rotation quaternion. Everything past 0x30 has not been decoded and is presumably flags or ids.

PlayerCheckpoint is therefore essentially a full Locator, position plus rotation, with some extra metadata. This was confirmed by comparing the decoded values against the real in-game position at the same moment: X was 271.098 against a decoded 271.97, Y was 17.878 against a decoded 20.55, and Z was -527.721 against a decoded -529.4. The small gaps are probably interpolation between the checkpoint and the live position.

### Full signature of TrySpawnPlayerAtContinue

```
TypedProcessHandle<Process>* TrySpawnPlayerAtContinue(
    TypedProcessHandle<Process>* retOut,          // rcx, hidden return slot, the struct is too big for rax
    int charIndex,                                 // rdx, 0 means Ellie, the only playable character in the tested sections
    const DC::Continue* continueData,              // r8, heap object (address range 0x91...), probably safe as a raw pointer
    const Locator* locA,                           // r9, NULL in every natural call observed
    const Locator* locB,                           // stack, also NULL in every natural call observed
    const GameSave::PlayerCheckpoint* checkpoint   // stack, points into the game thread's stack, invalidated within a few frames
);
```

The important part is that continueData and especially checkpoint point into memory that can be reused very quickly, since checkpoint lives on the game thread's stack. For a manual, deferred call (for example one triggered by a keypress), these buffers need to be deep copied at capture time, keeping only raw pointers is not safe.

## 4. Explored and abandoned paths

### SchemaRespawner::SpawnNpc and InitRespawner, abandoned

After fixing an offset transcription bug, a 4/7 mixup while copying values from an x64dbg screenshot, the real offsets turned out to be 0x442B80 and 0x4423C0 instead of the originally used 0x7442B80 and 0x7443C0. With the fix applied, the hooks install correctly but never trigger during normal gameplay, verified across several sessions with active combat.

The cause was found by walking back through the disassembly history: SchemaRespawner::SpawnNpc is a dev menu stub tied to an internal QA test level (DC file ss-test-schema-respawner.bin). It spawns an NPC at the crosshair position from the dev menu, it is not a real gameplay system, regardless of which offset is used.

### Archetype swap inside Npc::Init, abandoned

The idea was to mutate the StringId64 archetype hash inside Npc::Init before the original call ran, to make an infected spawn as Dina instead. This turned out to be too late, the object's vtable is already fixed at allocation time by that point.

### Archetype swap inside ProcessSpawnInfo, before Process::SpawnProcess, abandoned

The follow up idea was to mutate the hash at processSpawnInfo + 0x08 before calling Process::SpawnProcess, so the engine would pick the correct vtable from the start. The swap was conditioned on an exact match of the source hash (0x9AC5FBA6AD7337B9, generic Infected) against the target hash (0xF46F927358AB6273, Dina), so it would never touch the thousands of other spawns happening for VFX, sounds, and items.

The code for this is still present in dllmain.cpp behind the ENABLE_ARCHETYPE_SWAP flag, currently set to 0. It was abandoned due to a mismatch on m_pRecord, not investigated further at the time. The current preferred lead is TrySpawnPlayerAtContinue, which spawns a real Player directly instead of disguising an Npc as one.

### External open source mods, ruled out as a reference

luanaticc/TLOU2-BetaTest-ModMenu exposes a SpawnEntity() function that only contains a printf, no real hook or memory manipulation logic, consistent with the repository's own disclaimer that many functions are placeholders.

xwzrdx/TLOU2 does not publish any source code, only a compiled binary, and its features are unrelated (FOV, infinite resources).

The paid mod by jedijosh920 (Ko-fi) is the only third party implementation confirmed to actually work for spawning, but it was deliberately ruled out since this project avoids depending on closed source paid code.

### Spawn detection through hooking one exact function, replaced

The initial approach was to hook one specific spawn function and wait for it to trigger. This was replaced by generic passive detection: any new entity is detected through CharacterMotionMatchLocomotion::Update, which was confirmed to run for absolutely every entity in the scene, player, companion, and NPCs alike, not just the player.

Two failed attempts happened before landing on the current reliable method, deduplication by the name at offset 0x050 described in section 3. Deduplication by locomotion object address failed because horses reallocate a new sub object every time their gait changes (walk, trot, gallop), producing repeated false positives. Deduplication by the parent pointer at offset 0x008 also failed, because that pointer targets a temporary wrapper drawn from a rotating pool, recreated in a loop independently of the actual character it represents.

### Finding a DC source file by searching raw text, abandoned

An attempt was made to find the source .bin file for an encounter (for example npc-runner-hear-inside-1) by running findstr over the raw DC files. This consistently failed, returning zero results even when searching for the exact string.

The cause is that Naughty Dog's DC format stores identifiers as 64 bit hashes, never as plain text on disk. The readable text seen in memory dumps comes from the engine resolving hash to string live, through its internal table, which matches an earlier finding that the scripting engine resolves function calls by name hash. It does not come from the .bin file itself.

The unfinished follow up idea is to use dconstruct, which has access to sidbase.bin for resolving hashes, to scan every DC file in the level and search for the resolved text inside the disassembled output. The end goal would be to locate the exact encounter entry, duplicate it while swapping its archetype for Player Ellie, which is already located inside spawn-character.bin, and repackage it as a pak68 for ndmodloader. That approach would sidestep the need to hook a spawn function by hand entirely.

## 5. The spawn-character.bin DC file

Contains 46 spawnable characters reachable from the dev menu, using an npc-manual-spawn-params structure (faction, archetype, weapon loadout). Playable characters include Player Ellie, Player Joel, Player Abby, and Player Dina among others. NPC entries include Militia Pistol, Infected Runner, and Infected Clicker among others.

The DC function tied to the dev menu spawn is:

```
wait-spawn-npc-debug(
    bound-frame,    // position and rotation
    name,           // NPC name
    art-group,      // art group
    spawn-class,    // spawn class
    archetype,      // archetype
    weapon-loadout, // weapons
    0, 0            // flags
)
```

## 6. What these findings confirm about the game

The PC binary contains a complete, non trivial networking system inherited from Factions and The Last of Us Online: movement serialization, character snapshots (0x2290 bytes), weapon and grenade and effect and animation syncing, matchmaking, and sessions. Functions like SendNetEventCoopTeamFailed and SendNetEventLateJoinStartGame explicitly confirm that a co-op mode existed in the code, complete with late join handling already implemented, which lines up with the previously known existence of The Last of Us Online before it was cancelled.

This code is present but dead in solo play. Nothing activates it outside a multiplayer context, which is why it has to be triggered manually, through hooks and forged calls, rather than simply flipped on as a hidden feature.

## 7. State of the synchronization pipeline

Instance 1 acts as the reference. Its CharacterMotionMatchLocomotion::Update hook reads the position at offsets 0x158, 0x154, and 0x150, and sends it over UDP to the other instance via sendto(). Instance 2 receives the X, Y, Z values over UDP and writes them into its own companion object at the same offsets, so the companion visually follows Ellie's movement.

What works: Ellie's position on instance 1 is read correctly, transmitted over UDP, and applied to the companion object on instance 2 in real time.

What does not work yet: the second "player," triggered by F10 through TrySpawnPlayerAtContinue, is not a real second Process that can be controlled independently. In its current state, the original instance stays frozen and simply copies the other instance's movement instead of being replaced by, or turning into, a genuinely synchronized and controllable player. No NPC state machine synchronization (perception, alert, combat, dialogue) has been implemented at this stage, that remains the main obstacle to a real story co-op mode.

## 8. Ideas for continuing this work

Stabilize TrySpawnPlayerAtContinue so it produces a genuinely independent, controllable second Process, rather than a frozen visual clone.

Look into the dconstruct plus sidbase.bin approach for duplicating a DC encounter as Player Ellie, rather than forging the call in memory at runtime. This would be more robust, since it would not depend on the validity of a checkpoint pointer captured live.

Once the second player is stable, synchronize its inputs and camera, not just its position.

Look into RelationshipManager::GetDesiredDemeanor and RelationshipManager::GetFinalDemeanor, the NPC demeanor state machine spotted but not yet hooked, as a possible entry point for synchronizing NPC combat state between the two instances.

Reuse the existing NetEventCharacterMove pipeline (Fill, Write, Execute) instead of the current custom UDP channel, to take advantage of the serialization the engine already has in place for characters.
