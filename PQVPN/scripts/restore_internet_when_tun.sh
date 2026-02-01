#!/usr/bin/env bash
# Ripristina la default route attraverso il gateway LAN quando esiste una TUN che cattura il traffico.
# Uso:
#  ./scripts/restore_internet_when_tun.sh           # dry-run (mostra le azioni)
#  ./scripts/restore_internet_when_tun.sh --apply   # applica effettivamente (richiede sudo)
#  ./scripts/restore_internet_when_tun.sh --tun pqvpn0  # forza l'interfaccia tun

set -euo pipefail
DRY_RUN=1
TUN_IF=""

usage(){
  cat <<EOF
Usage: $0 [--apply] [--dry-run] [--tun IF]
  --apply    : esegue i comandi (richiede sudo)
  --dry-run  : mostra i comandi senza eseguirli (default)
  --tun IF   : nome dell'interfaccia TUN (es. pqvpn0). Se omesso, viene rilevata automaticamente.
EOF
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) DRY_RUN=0; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --tun) shift; TUN_IF="$1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

cmd_echo(){
  echo "+ $*"
}

run_cmd(){
  if [[ $DRY_RUN -eq 1 ]]; then
    cmd_echo "$*"
  else
    cmd_echo "(applico) $*"
    if [[ $EUID -ne 0 ]]; then
      echo "Sto per eseguire comandi di rete: verrà richiesto sudo."
      sudo bash -c "$*"
    else
      bash -c "$*"
    fi
  fi
}

# rileva interfaccia TUN se non fornita
if [[ -z "$TUN_IF" ]]; then
  # priorità a pqvpn0 se esiste
  if ip link show pqvpn0 >/dev/null 2>&1; then
    TUN_IF="pqvpn0"
  else
    # cerca la prima interfaccia che contiene 'tun' o 'pqvpn' o 'tun' device
    TUN_IF=$(ip -o link show | awk -F': ' '/tun|pqvpn/{print $2; exit}') || true
  fi
fi

if [[ -z "$TUN_IF" ]]; then
  echo "Nessuna interfaccia TUN trovata automaticamente. Specificane una con --tun.";
  exit 3
fi

echo "Interfaccia TUN: $TUN_IF"

# verifica se esiste una default route via la TUN
DEFAULTS_VIA_TUN=$(ip route show | awk -v tun="$TUN_IF" '$1=="default" && index($0, "dev " tun)>0 {print $0}') || true
# fallback: cerca qualsiasi default che abbia dev TUN_IF
if [[ -z "$DEFAULTS_VIA_TUN" ]]; then
  if ip route show | grep -q "^default" && ip route show | grep "^default" | grep -q "dev $TUN_IF"; then
    DEFAULTS_VIA_TUN=$(ip route show | grep "^default" | grep "dev $TUN_IF")
  fi
fi

if [[ -n "$DEFAULTS_VIA_TUN" ]]; then
  echo "Trovata default route instradata via $TUN_IF:"
  echo "$DEFAULTS_VIA_TUN"
else
  echo "Non ho trovato una default route instradata direttamente su $TUN_IF."
fi

# trova gateway LAN non via TUN (cerca una default che non usi il TUN)
GATEWAY=$(ip route | awk -v tun="$TUN_IF" '$1=="default" && index($0, "dev " tun)==0 {print $3; exit}') || true

# se non trovato, usa ip route get 8.8.8.8 per dedurre via/dev
if [[ -z "$GATEWAY" ]]; then
  R=$(ip route get 8.8.8.8 2>/dev/null || true)
  if [[ $R =~ via[[:space:]]([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
    GATEWAY=${BASH_REMATCH[1]}
  fi
  if [[ -z "$GATEWAY" ]]; then
    echo "Impossibile determinare il gateway LAN. Output di 'ip route get 8.8.8.8':"
    echo "$R"
    exit 4
  fi
fi

# trova interfaccia di uscita associata al gateway
OUT_IF=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)
if [[ -z "$OUT_IF" ]]; then
  # prova a dedurla cercando la route che contiene il gateway
  OUT_IF=$(ip route | awk -v gw="$GATEWAY" '$0 ~ gw {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)
fi

if [[ -z "$OUT_IF" ]]; then
  echo "Impossibile determinare l'interfaccia di uscita. Gateway trovato: $GATEWAY";
  echo "Mostro le default route correnti:";
  ip route show | sed -n '1,200p'
  exit 5
fi

echo "Gateway LAN: $GATEWAY"
echo "Interfaccia di uscita LAN: $OUT_IF"

# Comandi da eseguire
CMDS=()
# rimuovi default via TUN se presente
if ip route show | grep -q "^default" && ip route show | grep "^default" | grep -q "dev $TUN_IF"; then
  CMDS+=("ip route del default dev $TUN_IF || true")
fi
# aggiungi/replace default via gateway LAN
CMDS+=("ip route replace default via $GATEWAY dev $OUT_IF")

# mostra/ejegue
echo "\nAzioni proposte:"
for c in "${CMDS[@]}"; do
  echo "  $c"
done

if [[ ${#CMDS[@]} -eq 0 ]]; then
  echo "Nessuna modifica necessaria."
  exit 0
fi

if [[ $DRY_RUN -eq 1 ]]; then
  echo "Eseguire con --apply per applicare i comandi (verrà chiesto sudo)."
  exit 0
fi

# applica i comandi
for c in "${CMDS[@]}"; do
  run_cmd "$c"
done

echo "Operazione completata. Verifica con: ip route show && ip route get 8.8.8.8"
