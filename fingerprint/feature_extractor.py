"""Extract 44 byte-derived features: 30 response features, seven probe features and seven request/response relations. Feature order must match the Go extractor."""

import math
from typing import Dict, List, Optional
from collections import Counter

from tqdm import tqdm

class ResponseFeatureExtractor:
    """Extract 30+7+7=44 features from (request, response) for service classification."""

    # --- Response features (30) ---

    def _extract_response_features(self, resp: bytes) -> Dict[str, float]:
        features = {}

        # Basic statistics (6)
        features["resp_len"] = len(resp)
        if resp:
            byte_values = list(resp)
            features["resp_entropy"] = self._shannon_entropy(byte_values)
            features["resp_byte_mean"] = sum(byte_values) / len(byte_values)
            features["resp_byte_std"] = self._std(byte_values)
            sorted_vals = sorted(byte_values)
            mid = len(sorted_vals) // 2
            features["resp_byte_median"] = (
                (sorted_vals[mid - 1] + sorted_vals[mid]) / 2
                if len(sorted_vals) % 2 == 0
                else sorted_vals[mid]
            )
            features["resp_n_unique_bytes"] = len(set(byte_values))
        else:
            features["resp_entropy"] = 0.0
            features["resp_byte_mean"] = 0.0
            features["resp_byte_std"] = 0.0
            features["resp_byte_median"] = 0.0
            features["resp_n_unique_bytes"] = 0

        # Header features (6)
        features["resp_first_byte"] = resp[0] if len(resp) >= 1 else 0
        features["resp_first_2_bytes"] = int.from_bytes(resp[:2], "big") if len(resp) >= 2 else 0
        features["resp_first_4_bytes"] = int.from_bytes(resp[:4], "big") if len(resp) >= 4 else 0
        features["resp_byte_at_6"] = resp[6] if len(resp) >= 7 else 0
        features["resp_byte_at_8"] = resp[8] if len(resp) >= 9 else 0
        features["resp_byte_at_12"] = resp[12] if len(resp) >= 13 else 0

        # Tail features (3)
        features["resp_last_byte"] = resp[-1] if len(resp) >= 1 else 0
        features["resp_last_2_bytes"] = int.from_bytes(resp[-2:], "big") if len(resp) >= 2 else 0
        features["resp_last_4_bytes"] = int.from_bytes(resp[-4:], "big") if len(resp) >= 4 else 0

        # Character composition (7)
        if resp:
            n = len(resp)
            null_count = resp.count(b"\x00")
            features["resp_null_ratio"] = null_count / n
            printable_count = sum(1 for b in resp if 0x20 <= b <= 0x7E)
            features["resp_printable_ratio"] = printable_count / n
            features["resp_is_ascii"] = float(all(0x20 <= b <= 0x7E or b in (0x0A, 0x0D, 0x09) for b in resp))
            features["resp_has_crlf"] = float(b"\r\n" in resp)
            features["resp_has_null"] = float(null_count > 0)
            features["resp_has_high_bytes"] = float(any(b > 0x7F for b in resp))
            letter_count = sum(1 for b in resp if (0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A))
            features["resp_letter_ratio"] = letter_count / n
        else:
            features["resp_null_ratio"] = 0.0
            features["resp_printable_ratio"] = 0.0
            features["resp_is_ascii"] = 0.0
            features["resp_has_crlf"] = 0.0
            features["resp_has_null"] = 0.0
            features["resp_has_high_bytes"] = 0.0
            features["resp_letter_ratio"] = 0.0

        # Structural features (5)
        if resp:
            has_repeated, max_run = self._run_length(resp)
            features["resp_has_repeated_bytes"] = float(has_repeated)
            features["resp_max_run_length"] = max_run
            features["resp_len_mod_8"] = len(resp) % 8
            features["resp_len_mod_16"] = len(resp) % 16
            features["resp_is_power_of_2_len"] = float(len(resp) > 0 and (len(resp) & (len(resp) - 1)) == 0)
        else:
            features["resp_has_repeated_bytes"] = 0.0
            features["resp_max_run_length"] = 0
            features["resp_len_mod_8"] = 0
            features["resp_len_mod_16"] = 0
            features["resp_is_power_of_2_len"] = 0.0

        # N-gram features (3)
        if len(resp) >= 2:
            two_grams = Counter(resp[i : i + 2] for i in range(len(resp) - 1))
            features["resp_n_2grams"] = len(two_grams)
            features["resp_2gram_ratio"] = len(two_grams) / (len(resp) - 1)
            most_common_count = two_grams.most_common(1)[0][1]
            features["resp_most_common_2gram_freq"] = most_common_count / (len(resp) - 1)
        else:
            features["resp_n_2grams"] = 0
            features["resp_2gram_ratio"] = 0.0
            features["resp_most_common_2gram_freq"] = 0.0

        return features

    # --- Request features (7) ---

    def _extract_request_features(self, req: bytes) -> Dict[str, float]:
        features = {}
        features["req_len"] = len(req)
        features["req_entropy"] = self._shannon_entropy(list(req)) if req else 0.0
        features["req_first_byte"] = req[0] if len(req) >= 1 else 0
        features["req_first_2_bytes"] = int.from_bytes(req[:2], "big") if len(req) >= 2 else 0
        features["req_first_4_bytes"] = int.from_bytes(req[:4], "big") if len(req) >= 4 else 0
        features["req_last_byte"] = req[-1] if len(req) >= 1 else 0
        features["req_last_2_bytes"] = int.from_bytes(req[-2:], "big") if len(req) >= 2 else 0
        return features

    # --- Relationship features (7) ---

    def _extract_relationship_features(
        self, req: bytes, resp: bytes,
        req_feats: Dict[str, float], resp_feats: Dict[str, float],
    ) -> Dict[str, float]:
        features = {}

        req_len = req_feats["req_len"]
        resp_len = resp_feats["resp_len"]

        features["req_resp_len_ratio"] = req_len / max(resp_len, 1)
        features["req_resp_len_diff"] = abs(req_len - resp_len)
        features["req_resp_entropy_diff"] = abs(
            req_feats["req_entropy"] - resp_feats["resp_entropy"]
        )
        features["req_resp_first_byte_match"] = float(
            len(req) >= 1 and len(resp) >= 1 and req[0] == resp[0]
        )
        features["req_resp_byte_mean_diff"] = abs(
            (sum(req) / len(req) if req else 0.0) - resp_feats["resp_byte_mean"]
        )
        features["req_resp_unique_bytes_ratio"] = (
            len(set(req)) / max(len(set(resp)), 1) if resp else 0.0
        )
        features["resp_shorter_than_req"] = float(resp_len < req_len)

        return features

    # --- Public API ---

    def extract(self, response_hex: str, request_hex: Optional[str] = None) -> Dict[str, float]:
        """
        Extract all 44 features from a service response (and optional request).

        Args:
            response_hex: Response bytes as hex string
            request_hex: Request bytes as hex string (optional, for Approach C)

        Returns:
            Dict of feature_name -> value
        """
        resp = bytes.fromhex(response_hex) if response_hex else b""

        # Response features (30)
        features = self._extract_response_features(resp)

        if request_hex is not None:
            req = bytes.fromhex(request_hex) if request_hex else b""

            # Request features (7)
            req_feats = self._extract_request_features(req)
            features.update(req_feats)

            # Relationship features (7)
            rel_feats = self._extract_relationship_features(req, resp, req_feats, features)
            features.update(rel_feats)

        return features

    def extract_batch(self, samples: List[Dict], show_progress: bool = True,
                      label_key: str = "service") -> tuple:
        """Extract features from a batch of fingerprint samples."""
        feature_names = None
        X = []
        y = []

        iterator = tqdm(samples, desc="Extracting features", unit="sample",
                        ncols=100, disable=not show_progress)
        for sample in iterator:
            request_hex = sample.get("request_hex")
            feats = self.extract(sample["response_hex"], request_hex)
            if feature_names is None:
                feature_names = list(feats.keys())
            X.append([feats[k] for k in feature_names])
            y.append(sample[label_key])

        return X, y, feature_names

    # --- Utilities ---

    @staticmethod
    def _shannon_entropy(byte_values: List[int]) -> float:
        if not byte_values:
            return 0.0
        counts = Counter(byte_values)
        total = len(byte_values)
        entropy = 0.0
        for c in counts.values():
            p = c / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _std(values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        return math.sqrt(variance)

    @staticmethod
    def _run_length(data: bytes) -> tuple:
        """Returns (has_run_3plus, max_run_length)."""
        if not data:
            return False, 0
        max_run = 1
        current_run = 1
        for i in range(1, len(data)):
            if data[i] == data[i - 1]:
                current_run += 1
                if current_run > max_run:
                    max_run = current_run
            else:
                current_run = 1
        return max_run >= 3, max_run