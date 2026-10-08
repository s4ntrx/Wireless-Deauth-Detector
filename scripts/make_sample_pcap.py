import sys
from pathlib import Path

from scapy.utils import wrpcap

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.factories import sample_attack_capture  # noqa: E402

output = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "examples" / "sample_attack.pcap")
output.parent.mkdir(parents=True, exist_ok=True)
wrpcap(str(output), sample_attack_capture())
print(f"wrote {output}")
