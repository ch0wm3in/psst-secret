// X-Wing hybrid KEM (ML-KEM-768 + X25519), exposed to static/js/crypto.js.
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';

window.PsstPQ = { kem: ml_kem768_x25519 };
