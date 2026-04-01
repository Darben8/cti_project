# Data Validation Utilities

This module provides tools for assessing dataset quality, completeness, and readiness for CTI operations.

## Quick Start

```python
from utils.data_validation import DatasetQualityValidator
import pandas as pd

# Load your dataset
df = pd.read_csv("data/threat_events.csv")
df["date"] = pd.to_datetime(df["date"])

# Validate size
validator = DatasetQualityValidator()
size_check = validator.validate_dataset_size(df, "My Threats")
print(f"✅ {size_check['message']}")

# Validate time window
time_check = validator.validate_time_window(df, "date", "My Threats")
print(f"✅ {time_check['message']}")

# Validate per-source coverage
source_check = validator.validate_by_source(df, "source", min_rows=5)
for source, details in source_check.items():
    print(f"  {details['message']}")
```

## Constants & Thresholds

### Dataset Size Thresholds

```python
DatasetQualityValidator.MIN_ROWS_IDEAL = 1000          # Gold standard
DatasetQualityValidator.MIN_ROWS_ACCEPTABLE = 100      # Minimum for operations
```

### Time Window Thresholds

```python
DatasetQualityValidator.MIN_TIME_WINDOW_IDEAL = 180        # 6 months
DatasetQualityValidator.MIN_TIME_WINDOW_ACCEPTABLE = 30    # 1 month
```

---

## API Reference

### `validate_dataset_size(df, source_name, min_acceptable=None)`

Checks if a dataset has sufficient record count.

**Parameters:**
- `df` (pd.DataFrame): Dataset to validate
- `source_name` (str): Name of dataset (used in messages)
- `min_acceptable` (int, optional): Custom minimum threshold

**Returns:**
```python
{
    "is_valid": bool,           # Meets MIN_ROWS_ACCEPTABLE
    "meets_ideal": bool,         # Meets MIN_ROWS_IDEAL (1000)
    "row_count": int,           # Actual row count
    "source": str,              # Dataset name
    "message": str              # Auto-generated assessment
}
```

**Example:**
```python
size_check = validator.validate_dataset_size(df_threats, "Threat Events")
if not size_check["is_valid"]:
    st.warning(size_check["message"])
```

---

### `validate_time_window(df, date_column, source_name)`

Checks if data spans an adequate time period.

**Parameters:**
- `df` (pd.DataFrame): Dataset to validate
- `date_column` (str): Name of date column (e.g., "date", "created_at")
- `source_name` (str): Name of dataset

**Returns:**
```python
{
    "is_valid": bool,           # Meets MIN_TIME_WINDOW_ACCEPTABLE (30 days)
    "meets_ideal": bool,         # Meets MIN_TIME_WINDOW_IDEAL (180 days)
    "days_covered": int,        # Days between min and max date
    "date_min": str,            # Earliest date (YYYY-MM-DD)
    "date_max": str,            # Latest date (YYYY-MM-DD)
    "source": str,              # Dataset name
    "message": str              # Auto-generated assessment
}
```

**Example:**
```python
df["date"] = pd.to_datetime(df["date"])
time_check = validator.validate_time_window(df, "date", "Threat Events")
print(f"Coverage: {time_check['days_covered']} days")
print(f"Period: {time_check['date_min']} to {time_check['date_max']}")
```

---

### `validate_by_source(df, source_column, min_rows=None)`

Checks minimum record count per data source.

**Parameters:**
- `df` (pd.DataFrame): Dataset to validate
- `source_column` (str): Name of column containing source names
- `min_rows` (int, optional): Minimum records per source (default: 100)

**Returns:**
```python
{
    "source_name": {
        "row_count": int,         # Records for that source
        "is_valid": bool,         # Meets min_rows threshold
        "message": str            # Pre-formatted status message
    },
    ...
}
```

**Example:**
```python
source_check = validator.validate_by_source(df, "source", min_rows=5)
for source, details in source_check.items():
    st.caption(details["message"])
    # Output: "✅ PhishTank: 10 records (meets threshold)"
```

---

### `get_justification_for_small_datasets()`

Returns a detailed markdown explanation for why datasets below ideal thresholds still yield actionable intelligence.

**Returns:** str (markdown formatted)

**Example:**
```python
validator = DatasetQualityValidator()
if not size_check["meets_ideal"]:
    st.info(validator.get_justification_for_small_datasets())
```

---

## Integration in Streamlit Pages

### Basic Integration (Dashboard Example)

```python
import streamlit as st
from utils.data_validation import DatasetQualityValidator

# Load data
df = load_local_events()

# Validate
with st.expander("ℹ️ Data Quality & Completeness", expanded=False):
    validator = DatasetQualityValidator()
    size_check = validator.validate_dataset_size(df, "Threat Events")
    time_check = validator.validate_time_window(df, "date", "Threat Events")
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Records", size_check["row_count"])
        st.caption(f"{'✅' if size_check['is_valid'] else '⚠️'} {size_check['message']}")
    with col2:
        st.metric("Time Window (Days)", time_check["days_covered"])
        st.caption(f"{'✅' if time_check['is_valid'] else '⚠️'} {time_check['message']}")
    
    if not (size_check['meets_ideal'] or time_check['meets_ideal']):
        st.info(validator.get_justification_for_small_datasets())
```

---

## Configuration & Customization

### Default Thresholds

All thresholds are centralized in `config/data_standards.py`:

```python
MIN_ROWS_PER_DATASET = {
    "IDEAL": 1000,
    "ACCEPTABLE": 100,
    "CRITICAL_MINIMUM": 10
}

MIN_TIME_WINDOW_DAYS = {
    "IDEAL": 180,
    "ACCEPTABLE": 30,
    "CRITICAL_MINIMUM": 1
}
```

### Custom Thresholds

To apply custom minimum for a specific dataset:

```python
# Lower threshold for critical asset inventory (expert-curated, not sampled)
size_check = validator.validate_dataset_size(df_assets, "Critical Assets", min_acceptable=3)
```

---

## Message Formatting

The validator auto-generates contextually appropriate messages:

| Row Count | Message |
|-----------|---------|
| 1,000+ | ✅ Excellent coverage for trend analysis and statistical confidence. |
| 100–999 | ✅ Good pattern visibility; confidence grows with ongoing collection. |
| 10–99 | ⚠️ Minimal but actionable. Sufficient for pattern identification. |
| < 10 | ❌ Below minimum acceptable threshold. |

---

## Time Window Messages

| Days Covered | Message |
|--------------|---------|
| 180+ | ✅ Good for detecting sustained trends. |
| 30–179 | ⚠️ Short-term snapshot. Sufficient for recent threat identification. |
| 1–29 | ⚠️ Very limited. Halt analysis until data improves. |

---

## Practical Examples

### Example 1: Dashboard with Multi-Source Validation

```python
import streamlit as st
import pandas as pd
from utils.data_validation import DatasetQualityValidator

df = pd.read_csv("data/threat_events.csv")
df["date"] = pd.to_datetime(df["date"])

validator = DatasetQualityValidator()

# Overall checks
size = validator.validate_dataset_size(df, "Threat Events")
time = validator.validate_time_window(df, "date", "Threat Events")

# Per-source checks
sources = validator.validate_by_source(df, "source", min_rows=3)

st.subheader("Data Quality")
col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Events", size["row_count"])
    st.caption(size["message"])

with col2:
    st.metric("Time Window", f"{time['days_covered']}d")
    st.caption(time["message"])

with col3:
    st.metric("Sources", len(sources))
    for src, data in sources.items():
        st.caption(f"  {src}: {data['row_count']}")
```

### Example 2: Post-Load Validation with Gating

```python
import streamlit as st
from utils.data_validation import DatasetQualityValidator

@st.cache_data
def load_and_validate(filepath):
    df = pd.read_csv(filepath)
    validator = DatasetQualityValidator()
    check = validator.validate_dataset_size(df, "Dataset")
    
    if not check["is_valid"]:
        st.error(f"❌ Data not ready: {check['message']}")
        st.stop()
    
    return df

df = load_and_validate("data/events.csv")
# Only runs if validation passed
st.success("Data loaded and validated!")
```

### Example 3: Custom Metrics Report

```python
from utils.data_validation import generate_dataset_report

# Generate report for display
events_df = pd.read_csv("data/threat_events.csv")
assets_df = pd.read_csv("data/critical_assets.csv")

report = generate_dataset_report(events_df, assets_df)
st.markdown(report)
```

---

## Troubleshooting

### Issue: "Date column not found"
**Solution:** Ensure the date column name matches exactly:
```python
# ❌ Wrong
time_check = validator.validate_time_window(df, "Date", "Dataset")

# ✅ Correct
df["date"] = pd.to_datetime(df["date"])
time_check = validator.validate_time_window(df, "date", "Dataset")
```

### Issue: "is_valid returns False but I have data"
**Solution:** Check your minimum threshold:
```python
# Default: 100 rows
size_check = validator.validate_dataset_size(df)  # False if < 100

# Custom: 10 rows
size_check = validator.validate_dataset_size(df, min_acceptable=10)  # True if >= 10
```

### Issue: Time window shows 0 days
**Solution:** Ensure all records have valid dates:
```python
# Remove nulls before validating
df_clean = df.dropna(subset=["date"])
time_check = validator.validate_time_window(df_clean, "date", "Dataset")
```

---

## See Also

- [Data Quality Standards](../docs/DATA_QUALITY_STANDARDS.md) — Comprehensive policy documentation
- [Stakeholder Summary](../docs/STAKEHOLDER_DATA_SUMMARY.md) — Executive overview
- [Configuration](../config/data_standards.py) — Threshold constants
