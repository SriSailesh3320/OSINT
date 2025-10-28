# Social Media OSINT Analyzer

This provides an in-depth guide for the **Social Media OSINT Analyzer** script, focusing on Reddit and GNews platforms. It covers the purpose and role of every Python library used, explains code snippets, and helps understand how each component fits together.

---

## Overview

The **Social Media OSINT Analyzer** is a Python program that gathers OSINT (Open Source Intelligence) from Reddit and news articles through the GNews API for a given keyword or hashtag. It performs data collection, sentiment analysis, reporting, and exports results as visualizations and structured files (JSON, CSV, TXT).

---

## Library Usage and Purpose

### 1. `re`
- **Purpose**: Regular expression operations.
- **Usage**: Cleans text data by removing URLs and non-word characters before sentiment analysis, aiding in text pre-processing.
- **Snippet**:
  ```python
  cleaned_text = re.sub(r"http\S+", "", text)
  cleaned_text = re.sub(r"[^\w\s]", "", cleaned_text)
  ```

### 2. `json`
- **Purpose**: Handling JSON data serialization and parsing.
- **Usage**: Saves analysis results in a machine-readable format and processes API responses.
- **Snippet**:
  ```python
  with open(output_file, "w", encoding="utf-8") as f:
      json.dump(self.data, f, indent=4, ensure_ascii=False, default=str)
  ```

### 3. `csv`
- **Purpose**: Supports tabular data representation.
- **Usage**: Exports collected data into CSV files for easy inspection and interoperability with tools like Excel and pandas.
- **Snippet**:
  ```python
  df = pd.DataFrame(rows)
  df.to_csv(output_file, index=False, encoding="utf-8")
  ```

### 4. `praw`
- **Purpose**: Python Reddit API Wrapper for accessing Reddit.
- **Usage**: Fetches posts from Reddit programmatically using credentials.
- **Snippet**:
  ```python
  reddit = praw.Reddit(
      client_id=REDDIT_CLIENT_ID,
      client_secret=REDDIT_CLIENT_SECRET,
      user_agent=REDDIT_USER_AGENT
  )
  subreddit_obj = reddit.subreddit("all")
  for submission in subreddit_obj.search(self.keyword, limit=limit):
      # Collect post info
  ```

### 5. `datetime`
- **Purpose**: Date and time operations.
- **Usage**: Timestamps report creation and data collection events.
- **Snippet**:
  ```python
  self.data = {
      "keyword": keyword,
      "timestamp": datetime.now().isoformat(),
      # ...
  }
  ```

### 6. `time`
- **Purpose**: Time-related utilities, including delays and timestamps.
- **Usage**: Implements API rate-limiting pauses.
- **Snippet**:
  ```python
  time.sleep(0.2)  # Respect API rate limits
  ```

### 7. `textblob`
- **Purpose**: Natural language processing and sentiment analysis.
- **Usage**: Calculates polarity for sentiment classification of collected text from news or Reddit posts.
- **Snippet**:
  ```python
  blob = TextBlob(cleaned_text)
  polarity = blob.sentiment.polarity
  ```

### 8. `matplotlib.pyplot`
- **Purpose**: Data visualization and plotting.
- **Usage**: Generates four-panel sentiment analysis and data source charts.
- **Snippet**:
  ```python
  fig, axes = plt.subplots(2, 2, figsize=(14, 10))
  axes[0, 0].pie(sizes, labels=labels, autopct="%1.1f%%")
  axes[1, 0].hist(scores, bins=30)
  ```

### 9. `pandas`
- **Purpose**: Data manipulation and analysis.
- **Usage**: Converts data for CSV export, and supports processing results from multiple platforms.
- **Snippet**:
  ```python
  df = pd.DataFrame(rows)
  df.to_csv(output_file, index=False, encoding="utf-8")
  ```

### 10. `requests`
- **Purpose**: HTTP requests for web APIs.
- **Usage**: Calls GNews API to retrieve news articles matching the search keyword.
- **Snippet**:
  ```python
  response = requests.get(url, timeout=10)
  news_json = response.json()
  ```

### 11. `dotenv.load_dotenv`
- **Purpose**: Loads environment variables from .env files.
- **Usage**: Manages sensitive API credentials securely, preventing hardcoding in the script.
- **Snippet**:
  ```python
  load_dotenv()
  REDDIT_CLIENT_ID = os.getenv("REDDIT_CLIENT_ID")
  ```

### 12. `os`
- **Purpose**: Operating system interface for file, path, and environment variable management.
- **Usage**: Loads API keys, manages environment configuration.
- **Snippet**:
  ```python
  REDDIT_CLIENT_ID = os.getenv("REDDIT_CLIENT_ID")
  ```

---

## Key Code Snippets and Their Explanation

### Environment Variable Loading

```python
load_dotenv()
REDDIT_CLIENT_ID = os.getenv("REDDIT_CLIENT_ID")
GNEWS_API_KEY = os.getenv("GNEWS_API_KEY")
```
*Loads API credentials from the .env file so that sensitive information is not present in code directly.*

---

### Data Collection from Reddit

```python
reddit = praw.Reddit(
    client_id=REDDIT_CLIENT_ID,
    client_secret=REDDIT_CLIENT_SECRET,
    user_agent=REDDIT_USER_AGENT
)
subreddit_obj = reddit.subreddit("all")
for submission in subreddit_obj.search(self.keyword, limit=limit):
    # Extract post fields and append to data
```
*Authenticates and searches Reddit for posts matching the keyword, then collects relevant metadata.*

---

### News Article Search Using GNews API

```python
url = f"https://gnews.io/api/v4/search?q={self.keyword}&lang=en&max={max_articles}&token={GNEWS_API_KEY}"
response = requests.get(url, timeout=10)
news_json = response.json()
for article in news_json.get("articles", []):
    # Parse title, description, publish date, etc.
```
*Builds a query URL for the GNews search endpoint, retrieves results, and parses each article for essential fields.*

---

### Sentiment Analysis

```python
for text in self.all_texts:
    cleaned_text = re.sub(r"http\S+", "", text)
    cleaned_text = re.sub(r"[^\w\s]", "", cleaned_text)
    blob = TextBlob(cleaned_text)
    polarity = blob.sentiment.polarity
    # Classify sentiment
```
*Cleans each post/news item, runs sentiment detection, and aggregates positive, negative, and neutral results.*

---

### Visualization Logic

```python
fig, axes = plt.subplots(2, 2, figsize=(14, 10))
axes[0, 0].pie(sizes, labels=labels, autopct="%1.1f%%")
axes[0, 1].bar(labels, sizes, color=colors)
axes[1, 0].hist(scores, bins=30)
axes[1, 1].bar(platform_data.keys(), platform_data.values(), color=["#FF4500", "#0066CC"])
plt.savefig(output_file, dpi=300, bbox_inches="tight")
```
*Creates pie, bar, and histogram plots to visualize sentiment distribution and data sources, saving the figure as an image.*

---

### Report Generation and Export

```python
with open(output_file, "w", encoding="utf-8") as f:
    # Write headers, summary, sentiment interpretation, and conclusions in text format
```
*Produces a human-readable summary and interpretation of the OSINT analysis as a text report.*

---

## Summary of Workflow

1. **Initialization**: Instantiate the class with a keyword.
2. **Credential Loading**: Verify required API keys via environment variables.
3. **Data Collection**: Fetch matching Reddit posts and news articles.
4. **Text Aggregation**: Gather all titles and descriptions in a master list.
5. **Sentiment Analysis**: Classify each text, aggregate and quantify sentiment proportions.
6. **Visualization**: Generate plots displaying sentiment and data source breakdowns.
7. **Reporting**: Produce a comprehensive analysis in text form.
8. **Export**: Save results as `.json`, `.csv`, and `.txt` files for further use.

---

## Sample Usage

### Run the Analyzer

```python
if __name__ == "__main__":
    main()
```

**Command Line Interaction**:
```
$ python osint_analyzer.py
SOCIAL MEDIA OSINT ANALYZER - Reddit and GNews Only
====================================================
Enter keyword or hashtag to analyze: cyberattack
[*] Starting data collection...
[*] Searching Reddit for 'cyberattack'...
[+] Retrieved 42 Reddit posts
[*] Searching news articles for 'cyberattack' via GNews API...
[+] Retrieved 25 news articles
[*] Analyzing sentiment of 67 texts...
[*] Generating reports and visualizations...
[+] Visualization saved to sentiment_analysis.png
[+] Report saved to osint_report.txt
[+] JSON data saved to osint_data.json
[+] CSV data saved to osint_data.csv
[+] Analysis complete!
```

---

## Final Notes

- **API Credentials**: Ensure your `.env` file contains valid values for `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET`, `GNEWS_API_KEY`.
- **Dependencies**: All libraries must be installed (`pip install praw textblob matplotlib pandas python-dotenv requests`).
- **Extensibility**: The class structure allows for additional platforms and analytics in future versions.
- **Reporting**: Multiple export options support interoperability with analysis and reporting tools.

This document serves as both a technical walk-through and user reference for understanding and utilizing the Social Media OSINT Analyzer efficiently.
