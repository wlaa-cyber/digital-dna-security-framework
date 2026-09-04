"""
SIS - Structural Identity Similarity Calculator
------------------------------------------------

This module combines:

1. Structural consistency
2. Context consistency

into the final SIS score.

The structural similarity itself is calculated by the
existing Similarity Calculation Engine.

This module does not:
- recalculate graph similarity
- analyze raw system snapshots
- classify malware
- make a security decision
- modify the trusted baseline
"""


DEFAULT_STRUCTURAL_WEIGHT = 0.7
DEFAULT_CONTEXT_WEIGHT = 0.3


def _validate_numeric_score(
    value,
    name,
):
    """
    Validate a score in the range [0, 1].
    """

    if not isinstance(
        value,
        (int, float),
    ):
        raise TypeError(
            f"{name} must be numeric."
        )

    if not 0.0 <= float(value) <= 1.0:
        raise ValueError(
            f"{name} must be between 0.0 and 1.0."
        )


def _validate_weight(
    value,
    name,
):
    """
    Validate a non-negative weight.
    """

    if not isinstance(
        value,
        (int, float),
    ):
        raise TypeError(
            f"{name} must be numeric."
        )

    if float(value) < 0.0:
        raise ValueError(
            f"{name} must be non-negative."
        )


def _validate_weights(
    structural_weight,
    context_weight,
):
    """
    Validate SIS component weights.

    The weights must sum to 1.0.
    """

    _validate_weight(
        structural_weight,
        "structural_weight",
    )

    _validate_weight(
        context_weight,
        "context_weight",
    )

    total = (
        float(structural_weight)
        + float(context_weight)
    )

    if abs(total - 1.0) > 1e-9:
        raise ValueError(
            "structural_weight and context_weight "
            "must sum to 1.0."
        )


def calculate_structural_consistency(
    similarity_report,
):
    """
    Extract structural similarity from the existing
    similarity engine.

    The actual structural similarity calculation is NOT
    performed here.
    """

    if not isinstance(
        similarity_report,
        dict,
    ):
        raise TypeError(
            "similarity_report must be a dictionary."
        )

    if "similarity" not in similarity_report:
        raise ValueError(
            "similarity_report must contain "
            "'similarity'."
        )

    similarity = similarity_report[
        "similarity"
    ]

    if not isinstance(
        similarity,
        dict,
    ):
        raise TypeError(
            "similarity_report['similarity'] "
            "must be a dictionary."
        )

    required_keys = {
        "node_similarity",
        "edge_similarity",
        "structural_similarity",
    }

    missing = (
        required_keys
        - set(similarity.keys())
    )

    if missing:
        raise ValueError(
            "Missing structural similarity keys: "
            f"{sorted(missing)}"
        )

    node_similarity = similarity[
        "node_similarity"
    ]

    edge_similarity = similarity[
        "edge_similarity"
    ]

    structural_similarity = similarity[
        "structural_similarity"
    ]

    _validate_numeric_score(
        node_similarity,
        "node_similarity",
    )

    _validate_numeric_score(
        edge_similarity,
        "edge_similarity",
    )

    _validate_numeric_score(
        structural_similarity,
        "structural_similarity",
    )

    result = {
        "node_similarity": float(
            node_similarity
        ),
        "edge_similarity": float(
            edge_similarity
        ),
        "structural_similarity": float(
            structural_similarity
        ),
    }

    if "weights" in similarity:
        weights = similarity["weights"]

        if not isinstance(
            weights,
            dict,
        ):
            raise TypeError(
                "similarity['weights'] "
                "must be a dictionary."
            )

        if (
            "node_weight" in weights
            and "edge_weight" in weights
        ):
            node_weight = weights[
                "node_weight"
            ]

            edge_weight = weights[
                "edge_weight"
            ]

            _validate_weight(
                node_weight,
                "node_weight",
            )

            _validate_weight(
                edge_weight,
                "edge_weight",
            )

            result["weights"] = {
                "node_weight": float(
                    node_weight
                ),
                "edge_weight": float(
                    edge_weight
                ),
            }

    return result


def calculate_sis(
    structural_result,
    context_result,
    structural_weight=DEFAULT_STRUCTURAL_WEIGHT,
    context_weight=DEFAULT_CONTEXT_WEIGHT,
):
    """
    Calculate the final SIS score.

    Formula:

        SIS =
            structural_weight * structural_consistency
            +
            context_weight * context_consistency

    Default weights:

        structural_weight = 0.7
        context_weight = 0.3

    Parameters
    ----------
    structural_result : dict
        Output from calculate_structural_consistency().

    context_result : dict
        Output from calculate_context_consistency().

    structural_weight : float
        Weight assigned to structural consistency.

    context_weight : float
        Weight assigned to contextual consistency.

    Returns
    -------
    dict
        Final SIS result.
    """

    if not isinstance(
        structural_result,
        dict,
    ):
        raise TypeError(
            "structural_result must be a dictionary."
        )

    if not isinstance(
        context_result,
        dict,
    ):
        raise TypeError(
            "context_result must be a dictionary."
        )

    if "structural_similarity" not in (
        structural_result
    ):
        raise ValueError(
            "structural_result must contain "
            "'structural_similarity'."
        )

    if "context_consistency" not in (
        context_result
    ):
        raise ValueError(
            "context_result must contain "
            "'context_consistency'."
        )

    structural_consistency = float(
        structural_result[
            "structural_similarity"
        ]
    )

    context_consistency = float(
        context_result[
            "context_consistency"
        ]
    )

    _validate_numeric_score(
        structural_consistency,
        "structural_consistency",
    )

    _validate_numeric_score(
        context_consistency,
        "context_consistency",
    )

    _validate_weights(
        structural_weight,
        context_weight,
    )

    structural_component = (
        float(structural_weight)
        * structural_consistency
    )

    context_component = (
        float(context_weight)
        * context_consistency
    )

    sis = (
        structural_component
        + context_component
    )

    return {
        "sis": float(sis),
        "structural_component": float(
            structural_component
        ),
        "context_component": float(
            context_component
        ),
        "weights": {
            "structural_weight": float(
                structural_weight
            ),
            "context_weight": float(
                context_weight
            ),
        },
    }