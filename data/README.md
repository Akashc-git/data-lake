# Real Datasets for CF-PS-15 Data Lake Access Control

This directory contains documentation and genuine reference datasets used for real data ingestion, schema validation, and pipeline curation.

## Approved Real Public Datasets

### 1. UCI Machine Learning Repository - Wine Quality Dataset
* **Source URL**: `https://archive.ics.uci.edu/static/public/186/wine+quality.zip` / `https://raw.githubusercontent.com/datasciencedojo/datasets/master/winequality-red.csv`
* **Original Publisher**: P. Cortez, A. Cerdeira, F. Almeida, T. Matos and J. Reis. Modeling wine preferences by data mining from physicochemical properties. Decision Support Systems, Elsevier, 47(4):547-553, 2009.
* **Format**: CSV
* **Key Attributes**:
  * `fixed_acidity`, `volatile_acidity`, `citric_acid`, `residual_sugar`, `chlorides`
  * `free_sulfur_dioxide`, `total_sulfur_dioxide`, `density`, `pH`, `sulphates`, `alcohol`, `quality`

### 2. UCI Machine Learning Repository - Iris Flower Dataset
* **Source URL**: `https://raw.githubusercontent.com/mwaskom/seaborn-data/master/iris.csv`
* **Original Publisher**: R.A. Fisher (1936), The use of multiple measurements in taxonomic problems.
* **Format**: CSV
* **Key Attributes**: `sepal_length`, `sepal_width`, `petal_length`, `petal_width`, `species`

### 3. NOAA Global Historical Climatology Network (GHCN) Daily Weather Sample
* **Source URL**: `https://raw.githubusercontent.com/datasets/global-temp/master/data/monthly.csv`
* **Format**: CSV / JSON

---

## Ingestion Rules

1. **Raw Immutability**: All original ingested files are preserved byte-for-byte in the private Backblaze B2 raw bucket (`B2_RAW_BUCKET`).
2. **SHA-256 Provenance**: Checksums are computed prior to upload and verified against cloud metadata upon storage.
3. **No Fabricated Records**: The application dashboard initializes with empty states until real datasets are ingested and processed.
