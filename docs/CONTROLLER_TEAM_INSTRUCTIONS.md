# Controller Team: Connection Fix Instructions

**From**: p-net analysis (pcap-verified, code-traced)
**Date**: 2026-01-31
**Scope**: Water-Controller repo (`mwilco03/Water-Controller`)

---

## Execution Order

Do not skip ahead. Each phase builds on the previous one.

| Phase | Goal | Validates |
|-------|------|-----------|
| 0 | Fix wire-level encoding bugs | RPC header, block headers, tag fields |
| 1 | DAP-only connect | Proves encoding is correct end-to-end |
| 2 | GSDML-based full connect | All slots from parsed GSDML |
| 3 | ModuleDiffBlock tolerance | Handles mismatched/missing modules |
| 4 | HTTP fallback (non-standard) | Insurance when GSDML unavailable |

---

## Phase 0: Fix Wire-Level Bugs

These five bugs were identified from raw hex analysis of `profi.pcapng`.
Every brute force variant fails due to at least one of these.

### Bug 0.1: ARBlockReq block_length includes padding (BLOCKING)

**File**: `src/profinet/profinet_rpc.c`
**Lines**: 469-479

**Current code** (broken):
```c
469    size_t name_len = strlen(params->station_name);
470    write_u16_be(buffer, (uint16_t)name_len, &pos);
471    memcpy(buffer + pos, params->station_name, name_len);
472    pos += name_len;
473    align_to_4(&pos);                    // padding included in pos
474
475    /* Fill AR block header */
476    size_t ar_block_len = pos - ar_block_start - 4;  // INCLUDES padding
477    size_t save_pos = ar_block_start;
478    write_block_header(buffer, BLOCK_TYPE_AR_BLOCK_REQ,
479                        (uint16_t)ar_block_len, &save_pos);
```

**Problem**: `align_to_4()` at line 473 advances `pos` before `ar_block_len` is
calculated at line 476. For station name "rtu-4b64" (8 bytes), the content is
52 + 8 = 60 bytes + 2 bytes version = 62. But `align_to_4` adds 2 padding bytes,
making block_length = 64.

p-net validates at `pf_cmrpc.c:1176`:
```c
if (p_block_header->block_length != block_length)  // 64 != 62 -> FAIL
```

Expected block_length = `54 + strlen(station_name)`.

**Fix**: Calculate block_length BEFORE alignment padding:
```c
469    size_t name_len = strlen(params->station_name);
470    write_u16_be(buffer, (uint16_t)name_len, &pos);
471    memcpy(buffer + pos, params->station_name, name_len);
472    pos += name_len;
473
474    /* Fill AR block header BEFORE adding inter-block padding */
475    size_t ar_block_len = pos - ar_block_start - 4;
476    size_t save_pos = ar_block_start;
477    write_block_header(buffer, BLOCK_TYPE_AR_BLOCK_REQ,
478                        (uint16_t)ar_block_len, &save_pos);
479
480    /* NOW align for next block */
481    align_to_4(&pos);
```

**Verification**: For station name "rtu-4b64": block_length should be
54 + 8 = 62 = 0x003E. Check wire bytes at offset 2-3 of ARBlockReq: `00 3E`.

---

### Bug 0.2: AlarmCRBlockReq tag headers are zero (BLOCKING after 0.1 fixed)

**File**: `src/profinet/profinet_rpc.c`
**Lines**: 584-585

**Current code** (broken):
```c
584    write_u16_be(buffer, 0, &pos);  /* Tag header high */
585    write_u16_be(buffer, 0, &pos);  /* Tag header low */
```

**Problem**: PROFINET requires VLAN tag headers for alarm CR.
- `tag_header_high` = 0xC000 (VLAN priority 6)
- `tag_header_low` = 0xA000 (VLAN priority 5)

p-net may accept 0x0000 in some versions but the spec requires these values.
Frame 1 in the pcap (the correct manual connect) uses C000/A000.

**Fix**:
```c
584    write_u16_be(buffer, 0xC000, &pos);  /* Tag header high (VLAN prio 6) */
585    write_u16_be(buffer, 0xA000, &pos);  /* Tag header low  (VLAN prio 5) */
```

---

### Bug 0.3: Verify RPC header byte order matches platform assumption

**File**: `src/profinet/profinet_rpc.c`
**Lines**: 194-206

**Current code**:
```c
195    hdr->server_boot = 0;
196    hdr->interface_version = 1;
197    hdr->sequence_number = ctx->sequence_number;
...
203    hdr->fragment_length = fragment_length;
```

**Assessment**: This uses direct struct assignment, which produces LE on LE platforms
(x86, ARM). Since `drep=0x10` declares LE, this is correct IF AND ONLY IF the
controller runs on a little-endian CPU.

The pcap showed some brute force frames with BE-encoded RPC fields (e.g.,
`if_version` as `00 00 00 01` instead of `01 00 00 00`). If the current code
produces correct LE output, then the pcap was captured from an older version.

**Action**: Add a compile-time assertion:
```c
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
               "RPC header relies on LE platform; use explicit conversion for BE");
```

If the controller ever needs to run on a BE platform, all these fields need
explicit LE conversion.

---

### Bug 0.4: NDR header must always be present

**File**: `src/profinet/profinet_rpc.c`
**Lines**: 264-316 (NDR writer)

**Context**: The 48-strategy system (`rpc_strategy.c`) was a debugging tool
to find a working wire format by brute force. Now that the correct format is
identified, the strategy cycling should be retired and replaced with a single
correct implementation.

p-net REQUIRES NDR. From `pf_cmrpc.c:4622-4634`:
```c
if (pf_get_ndr_data_req(&p_sess->get_info, &req_pos, &p_sess->ndr_data) != 0)
{
   LOG_ERROR(PF_RPC_LOG, "CMRPC(%d): Invalid NDR header.\n", __LINE__);
   ret = -1;
}
```

**Fix**: Always include the 20-byte NDR header. The correct wire format is:
- `UUID_WIRE_SWAP_FIELDS` (LE encoding per DREP=0x10)
- NDR always present
- `OPNUM_STANDARD` (0 = Connect)

The strategy system served its diagnostic purpose. The production code path
should use the single known-good format directly, not cycle through 48
combinations that include intentionally broken variants.

---

### Bug 0.5: ARBlockReq trailing buffer bytes

**File**: `src/profinet/profinet_rpc.c`
**Lines**: 471-473

The pcap shows 2 garbage bytes (`7B 32`) after the station name within the
ARBlockReq. These are the last 2 bytes of CMInitiatorObjectUUID that leaked
into the station name area. This is a consequence of Bug 0.1 — `align_to_4()`
advances `pos` into buffer space that wasn't explicitly zeroed.

**Fix**: After fixing Bug 0.1 (block_length before alignment), also zero the
padding bytes:
```c
    pos += name_len;

    /* Calculate block_length before padding */
    size_t ar_block_len = pos - ar_block_start - 4;
    /* ... write block header ... */

    /* Zero-fill alignment padding */
    while (pos % 4 != 0) {
        buffer[pos++] = 0;
    }
```

---

## Phase 1: DAP-Only Connect

After fixing Phase 0 bugs, test with the simplest possible connect request:
only DAP at slot 0, no application modules.

### What to send

**ExpectedSubmoduleBlockReq** with 1 API, 1 slot, 3 submodules:

```
API: 0x00000000
  Slot 0, ModuleIdent 0x00000001 (DAP)
    Subslot 0x0001, SubmoduleIdent 0x00000001 (DAP identity)
    Subslot 0x8000, SubmoduleIdent 0x00000100 (Interface)
    Subslot 0x8001, SubmoduleIdent 0x00000200 (Port)
```

These idents come from the RTU's GSDML (`GSDML-V2.4-WaterTreat-RTU-20241222.xml`):
- Line 95: DAP submodule = 0x00000001
- Line 116: Interface submodule = 0x00000100 at subslot 32768 (0x8000)
- Line 130: Port submodule = 0x00000200 at subslot 32769 (0x8001)

**NOTE**: The controller code in `gsdml_modules.h` already has the correct defines:
```c
#define GSDML_MOD_DAP           0x00000001
#define GSDML_SUBMOD_DAP        0x00000001
#define GSDML_SUBMOD_INTERFACE  0x00000100
#define GSDML_SUBMOD_PORT       0x00000200
```

These match the RTU code in `profinet_manager.c:885-919` and the GSDML.

### IOCRBlockReq for DAP-only

DAP has no IO data (PNET_DIR_NO_IO, input_size=0, output_size=0).
IOCRBlockReq still required but with minimal data lengths:

- Input IOCR: `data_length` = 40 (minimum: IOCS/IOPS overhead only)
- Output IOCR: `data_length` = 40

Frame IDs:
- Input: 0xC001 (RT_CLASS_1 input range)
- Output: 0x8001 (RT_CLASS_1 output range)

### IOCRBlockReq API entries

Each IOCR needs API entries listing which submodules contribute data:

```
Input IOCR:
  API 0x00000000, 3 IODataObjects:
    Slot 0 Subslot 0x0001 FrameOffset 0
    Slot 0 Subslot 0x8000 FrameOffset 0
    Slot 0 Subslot 0x8001 FrameOffset 0
  3 IOCS entries (same slots/subslots)

Output IOCR:
  API 0x00000000, 3 IODataObjects:
    Slot 0 Subslot 0x0001 FrameOffset 0
    Slot 0 Subslot 0x8000 FrameOffset 0
    Slot 0 Subslot 0x8001 FrameOffset 0
  3 IOCS entries (same slots/subslots)
```

### Strategy for Phase 1

Use exactly one strategy (no brute force):
- `UUID_WIRE_SWAP_FIELDS` (LE encoding per DREP)
- `NDR_REQUEST_PRESENT` (mandatory)
- `SLOT_SCOPE_DAP_ONLY`
- `TIMING_CONSERVATIVE` (relaxed timing for initial testing)
- `OPNUM_STANDARD` (0 = Connect)

### Expected response

If encoding is correct, p-net returns a Connect Response with:
- ARBlockRes (AR accepted)
- IOCRBlockRes (IOCR accepted)
- ModuleDiffBlock showing DAP matches

If ModuleDiffBlock shows all modules as `MODULE_STATE_PROPER`, the connect
succeeded. Proceed to Phase 2.

### What to verify in the response

1. Response `frag_len > 20` (not just an error)
2. ARBlockRes present (block_type 0x8101)
3. No PNIO error codes in the response

---

## Phase 2: GSDML-Based Full Connect

### Approach

Parse the GSDML XML file (`GSDML-V2.4-WaterTreat-RTU-20241222.xml`) to
build ExpectedSubmoduleBlockReq with all possible modules. The controller
should ship with (or fetch) this file — it does NOT need an HTTP API.

The GSDML defines these module types as usable in slots 1-246:

| Module | Ident (hex) | Ident (dec) | Submodule (hex) | Submodule (dec) | Direction | Data Size |
|--------|-------------|-------------|-----------------|-----------------|-----------|-----------|
| pH | 0x00000010 | 16 | 0x00000011 | 17 | INPUT | 5 bytes |
| TDS | 0x00000020 | 32 | 0x00000021 | 33 | INPUT | 5 bytes |
| Turbidity | 0x00000030 | 48 | 0x00000031 | 49 | INPUT | 5 bytes |
| Temperature | 0x00000040 | 64 | 0x00000041 | 65 | INPUT | 5 bytes |
| Flow | 0x00000050 | 80 | 0x00000051 | 81 | INPUT | 5 bytes |
| Level | 0x00000060 | 96 | 0x00000061 | 97 | INPUT | 5 bytes |
| Generic AI | 0x00000070 | 112 | 0x00000071 | 113 | INPUT | 5 bytes |
| Pump | 0x00000100 | 256 | 0x00000101 | 257 | OUTPUT | 4 bytes |
| Valve | 0x00000110 | 272 | 0x00000111 | 273 | OUTPUT | 4 bytes |
| Generic DO | 0x00000120 | 288 | 0x00000121 | 289 | OUTPUT | 4 bytes |

**Note**: Hex values are used in C code (`gsdml_modules.h` defines) and GSDML.
Decimal values appear in the HTTP `/api/v1/slots` JSON response and the SQLite
database. They are the same numbers: `0x10 == 16`, `0x100 == 256`.

### Building ExpectedSubmoduleBlockReq

The controller does NOT know which modules the RTU has plugged until the
Connect Response (ModuleDiffBlock). Two approaches:

**Approach A (Recommended)**: Send only DAP in ExpectedSubmoduleBlockReq.
Read the ModuleDiffBlock. If it shows MODULE_STATE_NO_MODULE for all
application slots, use Record Read 0xF844 (RealIdentificationData) to
discover what's actually plugged. Then release and reconnect with correct
layout.

**Approach B**: If the controller has prior knowledge (e.g., from a previous
successful connection, cached config, or user configuration through the HMI),
send the full expected layout. Handle ModuleDiffBlock for any mismatches.

### IOCRBlockReq data_length calculation

For each IOCR, sum the data sizes of all contributing submodules:

```
input_total  = sum of input_size for all INPUT submodules
output_total = sum of output_size for all OUTPUT submodules

Input IOCR data_length  = 40 + input_total + (number_of_input_submodules * 1)
Output IOCR data_length = 40 + output_total + (number_of_output_submodules * 1)
```

The `+1` per submodule accounts for the IOPS/IOCS byte per submodule in the
cyclic frame.

### File changes

**`src/profinet/profinet_rpc.c`** — ExpectedSubmoduleBlock builder (lines 592-672):
The current code at line 608 already iterates `params->expected_config[]`.
Ensure the caller populates this array from GSDML (not hardcoded).

**`src/registry/slot_manager.c`** — This is where slot configs are created.
Verify it builds `expected_config[]` dynamically from either:
- GSDML parse results
- Cached previous connection state
- User HMI configuration

---

## Phase 3: ModuleDiffBlock Tolerance

After a full connect, the response includes ModuleDiffBlock (block_type 0x8104)
listing module states:

| State | Value | Meaning | Action |
|-------|-------|---------|--------|
| MODULE_STATE_PROPER | 0x0000 | Module matches | Normal operation |
| MODULE_STATE_SUBSTITUTE | 0x0001 | Slot empty | Mark slot inactive, skip in IO map |
| MODULE_STATE_WRONG | 0x0002 | Different module | Use actual module's data format |
| MODULE_STATE_NO_MODULE | 0x0003 | Nothing plugged | Mark slot inactive |

### Rules

1. **DAP diff IS fatal** — if slot 0 doesn't match, abort and investigate
2. **Application module diff is NOT fatal** — adapt IO map at runtime
3. Log every diff at WARNING level
4. Update the slot manager's runtime config to reflect actual state
5. Recalculate cyclic IO frame offsets based on actual plugged modules

### File changes

The ModuleDiffBlock parser should be in the connect response handler.
Currently the strategy system treats any non-success response as a failure
and advances to the next strategy. After Phase 0-2 fixes produce a successful
connect, add diff parsing to the response handler.

**`src/profinet/ar_manager.c`** — Add ModuleDiffBlock parsing to the
connect response handler. Map each diff entry to the slot manager.

---

## Phase 4: HTTP Fallback (Non-Standard — Last Resort)

### Architecture concern

This creates a proprietary dependency: the controller will only work with
RTUs that implement this HTTP API. No other PROFINET device will have it.
Standard PROFINET mechanisms (GSDML + ModuleDiffBlock + Record Read 0xF844)
provide the same information without custom firmware.

### When to use

HTTP fallback should ONLY activate when:
1. GSDML file is not available to the controller
2. DAP-only connect + Record Read 0xF844 has failed
3. Standard discovery mechanisms are exhausted

### API Contract

The RTU team document (RTU_TEAM_INSTRUCTIONS.md, Section 2) contains the
full API contract. Both documents reference the same spec. Key points:

```
GET http://<rtu_ip>:9081/api/v1/slots
Content-Type: application/json
```

**Response format:**
```json
{
  "slot_count": 2,
  "slots": [
    {"slot": 1, "subslot": 1, "module_ident": 16, "submodule_ident": 17,
     "direction": "input", "data_size": 5},
    {"slot": 2, "subslot": 1, "module_ident": 256, "submodule_ident": 257,
     "direction": "output", "data_size": 4}
  ]
}
```

**Contract details** (see RTU doc for full field definitions):
- **Path**: `/api/v1/slots` (versioned, not `/slots`)
- **Idents**: Integer (decimal). 16 = pH sensor (0x10), 256 = Pump (0x100)
- **DAP**: NOT included. Slot 0 is always DAP — controller knows this from GSDML.
- **Source**: Database (`db_module_list()`), available before PROFINET init.
- **Errors**: HTTP 503 when subsystem unavailable. Connection refused = not ready.

### Controller-side implementation

**`web/api/app/api/v1/discover.py`** — The `probe-ip` endpoint (line 902)
already calls RTU HTTP. Extend it to also fetch `/api/v1/slots` when available.

**`src/profinet/profinet_rpc.c`** or a new file — Before building the
connect request, check if HTTP slot data is available. If so, use it to
populate `params->expected_config[]`. If not, fall through to DAP-only.

To build ExpectedSubmoduleBlockReq from the JSON response:
```c
for each slot in response.slots:
    expected_config[i].slot = slot.slot
    expected_config[i].subslot = slot.subslot
    expected_config[i].module_ident = slot.module_ident       // integer, use directly
    expected_config[i].submodule_ident = slot.submodule_ident // integer, use directly
    expected_config[i].is_input = (strcmp(slot.direction, "input") == 0)
    expected_config[i].data_size = slot.data_size
```

### Fallback chain pseudocode

```
1. Do we have GSDML for this device?
   YES → Parse GSDML, build full ExpectedSubmoduleBlockReq → Phase 2
   NO  → Continue

2. Do we have cached slot config from a previous connection?
   YES → Use cached config → Phase 2
   NO  → Continue

3. Can we reach RTU HTTP on port 9081?
   YES → GET /api/v1/slots
         200 with data → Build ExpectedSubmoduleBlockReq from JSON → Phase 2
         503 or empty  → Continue
   NO  → Continue (connection refused = RTU HTTP not available)

4. Fall back to DAP-only connect → Phase 1
   After connect, Record Read 0xF844 for actual slot layout
   Release, rebuild ExpectedSubmoduleBlockReq, reconnect → Phase 2
```

---

## DHCP / IP Address Handling

The controller documentation already states: "NEVER hardcode RTU IP addresses."
The controller discovers RTUs via DCP multicast, which works regardless of how
the RTU obtained its IP (DHCP or static).

**Do NOT use DCP Set to assign IP addresses.** The RTU's IP comes from the
network (DHCP) or its own static config. The controller reads it from the DCP
Identify Response and connects to whatever IP is reported.

Relevant code: `web/api/app/services/dcp_discovery.py` — DCP response parsing
extracts `device.ip_address` from the DCP response block (DCP_OPTION_IP).

**ACTION**: The Water-Controller repo's `CLAUDE.md` connection sequence diagram
shows "DCP Set (assign IP address)" at step 2. This contradicts the design
agreement. Update the diagram to show DCP Identify only — the controller
discovers the RTU's existing IP, it does not assign one. Remove or annotate
step 2 to read: "DCP Identify Response (read IP — do NOT use DCP Set)."

---

## Station Name Handling

The controller documentation already states: "RTU station_name comes from the
device itself via DCP discovery."

**Do NOT use DCP Set-Name.** The RTU generates its own name (`rtu-XXXX` from
MAC). The controller discovers it and uses it as-is.

The DCP Identify Response contains the station name in
DCP_OPTION_DEVICE / DCP_SUBOPTION_DEVICE_NAME. The controller parses this
at `dcp_discovery.py:175-180` and stores it as the RTU identifier.

**ACTION**: Same as the DHCP note above — remove DCP Set-Name from the
Water-Controller `CLAUDE.md` connection sequence. The controller reads the
station name from DCP Identify Response, it does not write one.

---

## Verification Checklist

After each phase, verify with a packet capture:

### Phase 0 verification
- [ ] ARBlockReq block_length = 54 + station_name_len (no padding)
- [ ] Wire bytes for block_length: `00 3E` for 8-char name
- [ ] AlarmCRBlockReq tag_header_high = `C0 00`, tag_header_low = `A0 00`
- [ ] NDR header present (20 bytes between RPC header and first block)
- [ ] RPC `frag_len` matches actual payload (in LE)
- [ ] RPC `if_version` = `01 00 00 00` (LE for value 1)
- [ ] RPC `seqnum` increments by 1 in LE

### Phase 1 verification
- [ ] RTU responds with FragLen > 20
- [ ] Response contains ARBlockRes (0x8101)
- [ ] Response contains IOCRBlockRes (0x8102)
- [ ] Response contains ModuleDiffBlock (0x8104)
- [ ] No PNIO error status in response

### Phase 2 verification
- [ ] ExpectedSubmoduleBlockReq lists all configured modules
- [ ] IOCRBlockReq data_length accounts for all submodule data sizes
- [ ] ModuleDiffBlock shows MODULE_STATE_PROPER for plugged modules
- [ ] Cyclic data exchange starts after ApplicationReady
