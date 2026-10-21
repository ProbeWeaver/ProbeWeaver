"""
Configuration for Protocol Fuzzer

All settings can be configured here. Command line arguments can override these values.

Parameter Groups:
  1. TARGET SERVICES - see services_config.py (re-exported below for back-compat)
  2. FUZZING PARAMETERS - Core fuzzing settings (mutations, timeout, workers)
  3. SEED SETTINGS - Input/output seed files and selection thresholds
  4. ADAPTIVE MUTATION - Dynamic resource allocation per service
  4b. REINFORCEMENT LEARNING - Field-level dual-posterior search
  4c-4g. SEARCH OBJECTIVE AND OPTIONAL ANALYSES
  5. OUTPUT SETTINGS - Result files and export options
  6. LOGGING SETTINGS - Log file configuration
  7. PATHS - Directory paths (rarely need to change)
  8. OPTIONAL RETRIEVAL SETTINGS - Spec and identification-rule generation
  9. FINGERPRINT MODEL - Fingerprint model settings
"""

import os

# ==================== 1. TARGET SERVICES ====================
# The full registry contains 113 configured endpoints grouped into 32 logical
# service clusters.  It lives in services_config.py and is re-exported here so
# existing ``import config; config.SERVICES`` callers keep working.

from services_config import SERVICES as SERVICES          # re-export for `config.SERVICES`
from services_config import SERVICES_TO_FUZZ as SERVICES_TO_FUZZ  # re-export for `config.SERVICES_TO_FUZZ`

from services_config import SERVICE_CLUSTERS as SERVICE_CLUSTERS
from services_config import cluster_of as cluster_of
from services_config import (
    IDENTIFICATION_CLUSTER_MERGE as IDENTIFICATION_CLUSTER_MERGE,
)
from services_config import (
    identification_cluster_of as identification_cluster_of,
)
from services_config import (
    IDENTIFICATION_CLUSTER_MEMBERS as IDENTIFICATION_CLUSTER_MEMBERS,
    identification_candidates as identification_candidates,
)
__all__ = [
    "SERVICES", "SERVICES_TO_FUZZ", "SERVICE_CLUSTERS", "cluster_of",
    "IDENTIFICATION_CLUSTER_MERGE", "IDENTIFICATION_CLUSTER_MEMBERS",
    "identification_cluster_of", "identification_candidates",
]

# ==================== 2. FUZZING PARAMETERS ====================
# Core fuzzing settings - frequently adjusted for optimization

# Number of parallel workers for fuzzing
# Increase for faster fuzzing (uses more CPU/memory), decrease to reduce resource usage
CONCURRENT_WORKERS = 6

# Service timeout in seconds
# Local services: 0.1-0.2s | Remote services: 0.5-1.0s

SERVICE_TIMEOUT = 0.1

BANNER_TIMEOUT = 0.03

# Maximum fuzzing iterations (multi-round fuzzing)
# 1 = single pass; 2+ = iterative fuzzing using discovered seeds
MAX_ITERATIONS = 2

# True sends each unique payload to the same-transport observation fleet and
# applies the resolved objective's candidate qualification.  False only emits
# mutations and therefore has no response facts or online candidate channels.
TEST_PACKETS = True

RAW_SEED_BASELINE_TEST = True

PROBE_TARGETS = []

REQUIRE_ORIGIN_TRIGGER = True

# Phase 2 parallel batch testing
# Number of mutations per batch submitted to thread pool
PHASE2_BATCH_SIZE = 500

# Max concurrent threads per process for Phase 2 parallel testing
# With 8 concurrent workers: total connections = 8 × this value
# 64 = conservative (512 total), 128 = aggressive (1024 total)
# Requires: sysctl net.ipv4.tcp_tw_reuse=1
PHASE2_PARALLEL_WORKERS = 16

# ==================== 3. SEED SETTINGS ====================
# Seed files and selection thresholds for multi-round fuzzing

# Input seed file (hex format with optional service tags)
# Format: hex_string,service1;service2;...
# Example: 414d515000010000,mqtt;amqp
SEEDS_INPUT_FILE = "seeds.txt"

# Output file for candidate seeds (set to None to disable saving)
SEEDS_OUTPUT_FILE = "outputs/seeds.txt"

# Static/legacy collection threshold in observed service clusters.  Formal
# ``multi_probe`` qualification instead uses the background-adjusted null threshold;
# this value remains the legacy fallback and an input to historical seed policies.
FINGERPRINT_COLLECTION_THRESHOLD = 4

# Static/legacy seed threshold. Search also has high-breadth and strict-target seed
# channels; keep this >= FINGERPRINT_COLLECTION_THRESHOLD for legacy reproduction.
SEED_SELECTION_THRESHOLD = 4

# Maximum seeds to keep per response combination group
# Prevents explosion of similar seeds; 3-10 recommended
MAX_SEEDS_PER_RESPONSE_GROUP = 1

# Seed selection strategy: 'hash' (diversity-based, recommended) or 'random'
SEED_SELECTION_STRATEGY = 'hash'

# Legacy static-threshold scaling by the number of configured endpoints in a
# transport campaign.  It does not participate in formal qualification.
# Set to 1.0 to keep the configured thresholds unchanged.
THRESHOLD_SCALE_FACTOR = 1.0

# Maximum fingerprints to keep per unique (service -> response) pattern
# Reduces duplicates in final output
MAX_FINGERPRINTS_PER_RESPONSE_PATTERN = 1

# ==================== 4. ADAPTIVE MUTATION ====================

ADAPTIVE_UPPER_THRESHOLD = 0.05
ADAPTIVE_LOWER_THRESHOLD = 0.005

ADAPTIVE_FUZZ_INITIAL = 4000
ADAPTIVE_FUZZ_MIN = 1000            
ADAPTIVE_FUZZ_MAX = 6000
ADAPTIVE_FUZZ_INCREASE_RATE = 0.3  
ADAPTIVE_FUZZ_DECREASE_RATE = 0.3  

SEED_BATCH_COUNT = 6

# ==================== 4b. REINFORCEMENT LEARNING PARAMETERS ====================

RL_ENABLED = True

RL_SAMPLING_POLICY = "objective"

RL_RANDOM_SEED = None

RL_PRIOR_BY_SCORE = {
    5: (50, 10),   # TERMINATOR  mean=0.83  strength=60
    4: (40, 10),   # OTHER       mean=0.80  strength=50
    3: (30, 10),   # STRUCTURE/LENGTH  mean=0.75  strength=40
    2: (20, 10),   # PAYLOAD     mean=0.67  strength=30
}

RL_PRIOR_DEFAULT = (20, 10)

RL_TEMPERATURE = 2.0

# Decay each utility head toward its prior without decaying the prior itself.

RL_DECAY = 0.7

RL_BATCH_SIZE = 50
RL_BATCH_MIN = 30

RL_MAX_FIELDS = 4

RL_PHASE1_RATIO = 0.3

RL_PHASE2_MULTI_FIELD_RATIO = 0.7

RL_STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache", "rl_state.json")

RL_STATE_ALLOW_LEGACY_MIGRATION = False

RL_STATE_STRICT_VALIDATION = True

RL_LOAD_ONLY = False

# ==================== 4c. SEARCH OBJECTIVE ====================

REWARD_MODE = "background_adjusted_breadth"
OBJECTIVE_VERSION = "background_adjusted_breadth"

SEMANTIC_CANDIDATE_TOP_K = 5

EXPLORATORY_TOP_K_PER_EXTRA = 3
RESPONSE_PHASE_SCHEMA_VERSION = 2

DEDUP_ENABLED = True
DEDUP_LEDGER_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".cache", "send_dedup.sqlite3")
DEDUP_LEASE_SECONDS = 900.0

MULTI_FIELD_CREDIT_MODE = "split"

LAMBDA_BREADTH = 0.5

BREADTH_PRIOR = (1.0, 1.0)

SERVICE_WEIGHT_PREVALENCE_ALPHA = 0.7

COLLECT_TARGET_REACHABILITY = True
MAX_TARGET_REACHABILITY_PER_PATTERN = 2    
MAX_TARGET_REACHABILITY_PER_SERVICE = 100  

REWARD_LOG_ENABLED = True
REWARD_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache", "reward_events")

CANDIDATE_STREAM_ENABLED = True
CANDIDATE_STREAM_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".cache", "candidate_streams")

CAMPAIGN_CHECKPOINT_ENABLED = True
CAMPAIGN_CHECKPOINT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".cache", "campaign_checkpoints")
CAMPAIGN_RESUME = False

# ==================== 4d. MULTI-OBJECTIVE ADAPTIVE & SEED POLICY (P1-5) ====================

ADAPTIVE_OBJECTIVE_MODE = "multiobjective_v1"

ADAPTIVE_PATTERN_TRACK_CAP = 4096

ADAPTIVE_POLICY_MIN_SAMPLES = 100

ADAPTIVE_REACH_LOW_THRESHOLD = 0.05
ADAPTIVE_REACH_HIGH_THRESHOLD = 0.5

ADAPTIVE_BREADTH_PROGRESS_MIN = 0.005

ADAPTIVE_NO_PROGRESS_PATIENCE = 3

ADAPTIVE_STRICT_REACH_THRESHOLD = 0.05
ADAPTIVE_HIGH_WEIGHT_THRESHOLD = 0.05
ADAPTIVE_MIN_EXPLORE_BUDGET = 3000

SEED_HIGH_BREADTH_ENABLED = True        
SEED_HIGH_BREADTH_THRESHOLD = 0.1

SEED_HIGH_BREADTH_MAX_PER_SERVICE = 2
SEED_STRICT_TARGET_ENABLED = True       
SEED_STRICT_TARGET_REACH_THRESHOLD = 0.05   

SEED_STRICT_TARGET_MAX_PER_SERVICE_PER_ROUND = 1

EARLY_STOP_ENABLED = True
EARLY_STOP_MIN_ROUNDS = 2               
EARLY_STOP_PATIENCE = 2                 
EARLY_STOP_MIN_NEW_CLUSTERS = 1         
EARLY_STOP_MIN_NEW_PATTERNS = 1         
EARLY_STOP_MIN_BREADTH_IMPROVEMENT = 0.005  
EARLY_STOP_MIN_REACH_IMPROVEMENT = 0.005    

# ==================== 4e. COMPATIBILITY CALIBRATION PRIOR (P1-6) ====================

COMPATIBILITY_PRIOR_MODE = "none"

COMPATIBILITY_PRIOR_ARTIFACT = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache", "compat_calibration.json")

COMPATIBILITY_PRIOR_STRENGTH = 10.0

COMPATIBILITY_EPSILON = 0.1

COMPATIBILITY_NEUTRAL_Q = 0.5

COMPATIBILITY_STRICT_VALIDATION = True

# ==================== 4f. RESPONSE DISTINGUISHABILITY (P1-7, offline) ====================

# harness（PW_Scanner/modules/fuzzing/identify_batch.go），Tier1(code+specific)

DISTINGUISHABILITY_MODE = "none"

DISTINGUISHABILITY_STRICT_VALIDATION = True

DISTINGUISHABILITY_EVAL_RATIO = 0.3        

DISTINGUISHABILITY_SPLIT_KEY = "response_identity"   # packet | packet_target_member | response_identity

DISTINGUISHABILITY_CHUNK_SIZE = 2000
DISTINGUISHABILITY_NOVELTY_CAP = 50000

DISTINGUISHABILITY_ZGRAB_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "PW_Scanner")
DISTINGUISHABILITY_GO_BIN = "go"
DISTINGUISHABILITY_HARNESS_TIMEOUT = 600.0

# ==================== 4f-2. BACKGROUND RESPONSE PROFILE ====================

BACKGROUND_PROFILE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache", "background_profile.json")
BACKGROUND_MIX_ETA = 0.5
BACKGROUND_HIGH_RATE = 0.8
BACKGROUND_HIGH_MASS_MAX = 0.1
BACKGROUND_GAMMA_CANDIDATES = (1.0, 2.0, 3.0)
BACKGROUND_NULL_QUANTILE = 0.95
PASSIVE_BANNER_WILSON_MIN = 0.8



# ==================== 5. OUTPUT SETTINGS ====================
# Result export configuration

# Main output file for fingerprint results (JSON format)
OUTPUT_FILE = "outputs/fingerprints.json"

# ==================== 6. LOGGING SETTINGS ====================
# Log file configuration

# Log directory
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "fuzzer.log")

# If True, log to file only; if False, also output to console
# Set False during debugging to see real-time output
LOG_TO_FILE_ONLY = True

# ==================== 7. PATHS ====================
# Directory paths - rarely need to change

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(BASE_DIR, ".cache")

# Directory containing protocol specification files
# Each service should have its own file: protocol/specs/{service}.py
PROTOCOL_SPECS_DIR = os.path.join(BASE_DIR, "protocol", "specs")

# ==================== 8. OPTIONAL RETRIEVAL SETTINGS ====================
# AI-assisted protocol-specification support.

# RAG embedding model (CPU-compatible)
# Options: BAAI/bge-m3 (best, GPU), BAAI/bge-base-en-v1.5 (balanced), BAAI/bge-small-en-v1.5 (lightweight)
EMBEDDING_MODEL_CPU = "BAAI/bge-base-en-v1.5"

# Local model path for RAG (optional, leave empty to download from HuggingFace)
# Use None to auto-detect from models/rag_embeddings/ directory
LOCAL_MODEL_PATH = None

# Force offline mode for HuggingFace (set True to never access network)
# When True, requires models to be pre-downloaded to LOCAL_MODEL_PATH
HF_HUB_OFFLINE = True

# RAG cache directory

# Agentic RAG settings

# ==================== 8b. RULE-GENERATION AGENT ====================

RULE_GEN_THETA = 0.9

RULE_GEN_TAU_OWN = 0.95         
RULE_GEN_TAU_OTHER = 0.02       

RULE_GEN_IDENTITY_COVERAGE_MIN = 0.90

RULE_GEN_ECHO_GUARD_MIN_CONSTANT_BYTES = 4

RULE_GEN_TOP_K_SHAPES = 20        
RULE_GEN_HEX_PREVIEW_BYTES = 64   
RULE_GEN_TEXT_PREVIEW_BYTES = 256 
RULE_GEN_PRINTABLE_RATIO = 0.6    

RULE_GEN_SAMPLE_PER_CLUSTER = 400    
RULE_GEN_NEGATIVES_PER_CLUSTER = 60  
RULE_GEN_MIN_SAMPLES = 20            

RULE_GEN_SUBSTRING_MIN_LEN = 8       
RULE_GEN_SUBSTRING_MAX_LEN = 64      
RULE_GEN_SUBSTRING_TOPN = 4          

RULE_GEN_CODE_ENABLE = True          
RULE_GEN_CODE_TIMEOUT = 10.0         
RULE_GEN_CODE_GO_BIN = "go"          
RULE_GEN_CODE_MIN_RECALL = 0.3       

RULE_GEN_POS_DISTINCT = 64           
RULE_GEN_SAMPLE_SEED = 12345         

RULE_GEN_OUTPUT_DIR = os.path.join(BASE_DIR, "fingerprint", "agent", "generated_rules")
RULE_GEN_OUTPUT = os.path.join(RULE_GEN_OUTPUT_DIR, "code_rules.json")
RULE_GEN_SKILL_PATH = os.path.join(BASE_DIR, ".agents", "skills", "rule-gen", "SKILL.md")

# ==================== 8c. MULTI-GRANULARITY IDENTIFICATION ====================

# --- Per-cluster implementation classifier ---
MEMBER_RF_MIN_ACCURACY           = 0.80   
MEMBER_RF_MIN_SAMPLES_PER_MEMBER = 20     
MEMBER_RF_MIN_SEPARABLE_MEMBERS  = 2      

MEMBER_RULES_OUTPUT     = os.path.join(BASE_DIR, "PW_Scanner", "member_rules.json")

# ==================== 9. FINGERPRINT MODEL ====================

FINGERPRINT_CONFIDENCE_THRESHOLD = 0.7
