"""Pairwise structural byte-overlap heuristics. These may inform a calibrated cold-start prior, but never partition services or reduce the observation fleet. Unknown specifications receive a neutral score, not exclusion."""

from typing import List, Dict
from dataclasses import dataclass, field

from protocol.field import UnifiedProtocolSpec, FieldDefinition, FieldType, SurvivalType, PositionedField

HEURISTIC_ALGORITHM_VERSION = 1

@dataclass
class FieldCompatibilityResult:
    """Structural compatibility facts for a field pair."""
    field1_name: str
    field2_name: str
    fusion_posibility: float  # 0.0 - 1.0
    has_overlap: bool  
    conflict_type: str  # "none", "survival_conflict", "structure_conflict", "compatible"
    reason: str

@dataclass
class ServiceCompatibilityResult:
    """Aggregated structural compatibility facts for two services."""
    service1: str
    service2: str
    fusion_score: float  
    can_trigger_response: bool  
    conflict_details: List[str] = field(default_factory=list)
    field_results: List[FieldCompatibilityResult] = field(default_factory=list)

class FieldCompatibilityCalculator:
    """Score field overlap and conflicts without sending packets."""

    def calculate(
        self,
        field1: PositionedField,
        field2: PositionedField
    ) -> FieldCompatibilityResult:
        """Calculate."""

        overlap = self._calculate_overlap(
            field1.start_byte, field1.end_byte,
            field2.start_byte, field2.end_byte
        )

        if overlap == 0:
            return FieldCompatibilityResult(
                field1_name=field1.field.name,
                field2_name=field2.field.name,
                fusion_posibility=1.0,
                has_overlap=False,
                conflict_type="none",
                reason="No position overlap - can coexist"
            )

        return self._calculate_with_overlap(field1.field, field2.field, overlap)

    def _calculate_overlap(self, s1, e1, s2, e2) -> int:
        """Calculate the overlap between nominal byte intervals."""
        return max(0, min(e1, e2) - max(s1, s2))

    def _calculate_with_overlap(
        self,
        f1: FieldDefinition,
        f2: FieldDefinition,
        overlap: int
    ) -> FieldCompatibilityResult:
        """Score compatibility inside the shared byte interval."""

        if f1.field_type == FieldType.SURVIVAL:
            return self._calculate_survival_conflict(f1, f2, overlap)
        elif f2.field_type == FieldType.SURVIVAL:
            return self._calculate_survival_conflict(f2, f1, overlap)
        elif f1.field_type == FieldType.STRUCTURE:
            return self._calculate_structure_conflict(f1, f2, overlap)
        elif f2.field_type == FieldType.STRUCTURE:
            return self._calculate_structure_conflict(f2, f1, overlap)
        else:
            
            return self._calculate_payload_compatible(f1, f2, overlap)

    def _calculate_survival_conflict(
        self,
        survival_field: FieldDefinition,
        other_field: FieldDefinition,
        overlap: int
    ) -> FieldCompatibilityResult:
        """Score conflicts involving survival-critical fields."""

        if other_field.field_type == FieldType.SURVIVAL:
            return self._check_survival_survival(survival_field, other_field, overlap)

        if other_field.field_type == FieldType.STRUCTURE:
            return self._check_survival_structure(survival_field, other_field, overlap)

        return FieldCompatibilityResult(
            field1_name=survival_field.name,
            field2_name=other_field.name,
            fusion_posibility=0.3,  
            has_overlap=True,
            conflict_type="survival_conflict",
            reason="Survival field overlaps with payload - may cause parsing issues"
        )

    def _check_survival_survival(
        self,
        f1: FieldDefinition,
        f2: FieldDefinition,
        overlap: int
    ) -> FieldCompatibilityResult:
        """Check incompatible survival-field values at overlapping bytes."""

        if (f1.survival_type == SurvivalType.CHECKSUM and
            f2.survival_type == SurvivalType.CHECKSUM):
            return FieldCompatibilityResult(
                field1_name=f1.name,
                field2_name=f2.name,
                fusion_posibility=0.0,  
                has_overlap=True,
                conflict_type="survival_conflict",
                reason="Two checksum fields overlap - different algorithms likely incompatible"
            )

        if (f1.survival_type == SurvivalType.CHECKSUM or
            f2.survival_type == SurvivalType.CHECKSUM):
            return FieldCompatibilityResult(
                field1_name=f1.name,
                field2_name=f2.name,
                fusion_posibility=0.1,  
                has_overlap=True,
                conflict_type="survival_conflict",
                reason="Checksum field overlaps with other survival field"
            )

        if f1.min_value is not None and f1.max_value is not None and \
           f2.min_value is not None and f2.max_value is not None:

            overlap_start = max(f1.min_value, f2.min_value)
            overlap_end = min(f1.max_value, f2.max_value)

            if overlap_start > overlap_end:
                
                return FieldCompatibilityResult(
                    field1_name=f1.name,
                    field2_name=f2.name,
                    fusion_posibility=0.0,  
                    has_overlap=True,
                    conflict_type="survival_conflict",
                    reason=f"Survival fields conflict: [{f1.min_value},{f1.max_value}] vs [{f2.min_value},{f2.max_value}] - packet will be dropped"
                )

            range1 = f1.max_value - f1.min_value
            range2 = f2.max_value - f2.min_value
            overlap_range = overlap_end - overlap_start

            if overlap_range == max(range1, range2):
                
                return FieldCompatibilityResult(
                    field1_name=f1.name,
                    field2_name=f2.name,
                    fusion_posibility=0.8,
                    has_overlap=True,
                    conflict_type="compatible",
                    reason="Survival fields fully compatible"
                )
            else:
                
                return FieldCompatibilityResult(
                    field1_name=f1.name,
                    field2_name=f2.name,
                    fusion_posibility=0.2,  
                    has_overlap=True,
                    conflict_type="survival_conflict",
                    reason="Survival fields partially overlap - may cause packet drop"
                )

        return FieldCompatibilityResult(
            field1_name=f1.name,
            field2_name=f2.name,
            fusion_posibility=0.1,  
            has_overlap=True,
            conflict_type="survival_conflict",
            reason="Survival field overlap - conservative estimate"
        )

    def _check_survival_structure(
        self,
        survival_field: FieldDefinition,
        structure_field: FieldDefinition,
        overlap: int
    ) -> FieldCompatibilityResult:
        """Check survival-field values against structural alternatives."""

        if structure_field.expected_values and \
           survival_field.min_value is not None and survival_field.max_value is not None:

            for val in structure_field.expected_values:
                if isinstance(val, bytes) and len(val) > 0:
                    val_int = int.from_bytes(val[:min(4, len(val))], 'big')
                    if not (survival_field.min_value <= val_int <= survival_field.max_value):
                        
                        return FieldCompatibilityResult(
                            field1_name=survival_field.name,
                            field2_name=structure_field.name,
                            fusion_posibility=0.0,  
                            has_overlap=True,
                            conflict_type="survival_conflict",
                            reason=f"Structure value {val.hex()} outside survival range [{survival_field.min_value},{survival_field.max_value}] - will drop"
                        )

        return FieldCompatibilityResult(
            field1_name=survival_field.name,
            field2_name=structure_field.name,
            fusion_posibility=0.5,  
            has_overlap=True,
            conflict_type="compatible",
            reason="Survival and structure overlap - may return error but will respond"
        )

    def _calculate_structure_conflict(
        self,
        structure_field: FieldDefinition,
        other_field: FieldDefinition,
        overlap: int
    ) -> FieldCompatibilityResult:
        """Score conflicts between structural fields."""

        # STRUCTURE vs STRUCTURE
        if other_field.field_type == FieldType.STRUCTURE:
            return self._check_structure_structure(structure_field, other_field, overlap)

        return FieldCompatibilityResult(
            field1_name=structure_field.name,
            field2_name=other_field.name,
            fusion_posibility=0.7,  
            has_overlap=True,
            conflict_type="compatible",
            reason="Structure overlaps with payload - may return error but will respond"
        )

    def _check_structure_structure(
        self,
        f1: FieldDefinition,
        f2: FieldDefinition,
        overlap: int
    ) -> FieldCompatibilityResult:
        """Compare structural alternatives over shared bytes."""

        vals1 = set(f1.expected_values) if f1.expected_values else set()
        vals2 = set(f2.expected_values) if f2.expected_values else set()

        if not vals1 or not vals2:
            
            return FieldCompatibilityResult(
                field1_name=f1.name,
                field2_name=f2.name,
                fusion_posibility=0.4,
                has_overlap=True,
                conflict_type="structure_conflict",
                reason="Structure overlap with unknown values"
            )

        intersection = vals1 & vals2
        if intersection:
            
            return FieldCompatibilityResult(
                field1_name=f1.name,
                field2_name=f2.name,
                fusion_posibility=0.9,
                has_overlap=True,
                conflict_type="compatible",
                reason=f"Shared values: {[v.hex() for v in intersection]}"
            )

        return FieldCompatibilityResult(
            field1_name=f1.name,
            field2_name=f2.name,
            fusion_posibility=0.5,  
            has_overlap=True,
            conflict_type="structure_conflict",
            reason="Structure fields no shared values - may return error but will respond"
        )

    def _calculate_payload_compatible(
        self,
        f1: FieldDefinition,
        f2: FieldDefinition,
        overlap: int
    ) -> FieldCompatibilityResult:
        """Score the more permissive overlap involving payload fields."""
        return FieldCompatibilityResult(
            field1_name=f1.name,
            field2_name=f2.name,
            fusion_posibility=0.95,  
            has_overlap=True,
            conflict_type="compatible",
            reason="Payload fields flexible - will return error but will respond"
        )

class CompatibilityGraph:
    """
    Pairwise structural-compatibility score provider.

    The historical edge-building and service-grouping APIs were removed after
    Search uses full same-transport observation.  The class name is kept
    because calibrated compatibility artifacts identify this score provider.
    """

    # Pairwise score labels only; these thresholds never filter runtime targets
    # or partition campaigns.
    CAN_FUSE_THRESHOLD = 0.3
    EASY_FUSE_THRESHOLD = 0.7

    def __init__(self):
        self.specs: Dict[str, UnifiedProtocolSpec] = {}
        self.calculator = FieldCompatibilityCalculator()

    def add_spec(self, spec: UnifiedProtocolSpec):
        """Register a bounded protocol profile."""
        self.specs[spec.name] = spec

    def calculate_fusion_score(
        self,
        spec1_name: str,
        spec2_name: str
    ) -> ServiceCompatibilityResult:
        """Calculate the pairwise structural compatibility score."""
        if spec1_name == spec2_name:
            return ServiceCompatibilityResult(
                service1=spec1_name,
                service2=spec2_name,
                fusion_score=1.0,
                can_trigger_response=True,
                field_results=[]
            )

        spec1 = self.specs.get(spec1_name)
        spec2 = self.specs.get(spec2_name)

        if not spec1 or not spec2:
            return ServiceCompatibilityResult(
                service1=spec1_name,
                service2=spec2_name,
                fusion_score=0.0,
                can_trigger_response=False,
                field_results=[]
            )

        field_results = []
        conflict_details = []

        spec1_fields = spec1.iter_positioned_fields()
        spec2_fields = spec2.iter_positioned_fields()

        for f1 in spec1_fields:
            for f2 in spec2_fields:
                result = self.calculator.calculate(f1, f2)
                field_results.append(result)

                if result.fusion_posibility < 0.3:
                    conflict_details.append(
                        f"{f1.field.name} <-> {f2.field.name}: {result.reason}"
                    )

        has_survival_conflict = any(
            r.conflict_type == "survival_conflict" and r.fusion_posibility == 0.0
            for r in field_results
        )

        if has_survival_conflict:
            
            fusion_score = 0.0
            can_trigger = False
        else:
            
            total = sum(r.fusion_posibility for r in field_results)
            fusion_score = total / len(field_results) if field_results else 0.0

            if any(r.fusion_posibility < 0.3 for r in field_results):
                fusion_score = min(fusion_score, 0.5)

            can_trigger = fusion_score >= self.CAN_FUSE_THRESHOLD

        return ServiceCompatibilityResult(
            service1=spec1_name,
            service2=spec2_name,
            fusion_score=fusion_score,
            can_trigger_response=can_trigger,
            conflict_details=conflict_details,
            field_results=field_results
        )
