import re
import json
import csv
import praw
from datetime import datetime
import time
from textblob import TextBlob
import matplotlib.pyplot as plt
import pandas as pd
import requests
from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables from .env file

REDDIT_CLIENT_ID = os.getenv("REDDIT_CLIENT_ID")
REDDIT_CLIENT_SECRET = os.getenv("REDDIT_CLIENT_SECRET")
REDDIT_USER_AGENT = os.getenv("REDDIT_USER_AGENT", "OSINT_Analyzer/1.0")
GNEWS_API_KEY = os.getenv("GNEWS_API_KEY")


class SocialMediaOSINT:
    def __init__(self, keyword, platforms=None):
        self.keyword = keyword
        self.platforms = platforms if platforms else ["reddit", "news"]
        self.data = {
            "keyword": keyword,
            "timestamp": datetime.now().isoformat(),
            "reddit": [],
            "news": [],
            "sentiment_analysis": {}
        }
        self.all_texts = []

    def search_reddit(self, limit=None):
        try:
            if not all([REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET, REDDIT_USER_AGENT]):
                print("[-] Reddit API credentials not available in environment variables")
                self.data["reddit"] = [{"error": "No API credentials"}]
                return

            print(f"[*] Searching Reddit for '{self.keyword}'...")
            reddit = praw.Reddit(
                client_id=REDDIT_CLIENT_ID,
                client_secret=REDDIT_CLIENT_SECRET,
                user_agent=REDDIT_USER_AGENT
            )
            posts = []
            subreddit_obj = reddit.subreddit("all")

            for submission in subreddit_obj.search(self.keyword, limit=limit):
                post_data = {
                    "platform": "reddit",
                    "id": submission.id,
                    "subreddit": submission.subreddit.display_name,
                    "title": submission.title,
                    "text": submission.selftext,
                    "author": str(submission.author),
                    "score": submission.score,
                    "num_comments": submission.num_comments,
                    "created_at": datetime.fromtimestamp(submission.created_utc).isoformat(),
                    "url": submission.url
                }
                posts.append(post_data)
                self.all_texts.append(f"{submission.title} {submission.selftext}")
            self.data["reddit"] = posts
            print(f"[+] Retrieved {len(posts)} Reddit posts")
        except ImportError:
            print("[-] praw not installed. Install with: pip install praw")
            self.data["reddit"] = [{"error": "praw not installed"}]
        except Exception as e:
            print(f"[-] Reddit search failed: {e}")
            self.data["reddit"] = [{"error": str(e)}]

    def search_news(self, max_articles=None):
        if not GNEWS_API_KEY:
            print("[-] GNews API key missing in environment variables")
            self.data["news"] = [{"error": "Missing GNews API key"}]
            return
        print(f"[*] Searching news articles for '{self.keyword}' via GNews API...")
        try:
            url = f"https://gnews.io/api/v4/search?q={self.keyword}&lang=en&max={max_articles}&token={GNEWS_API_KEY}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            news_json = response.json()
            articles = []
            for article in news_json.get("articles", []):
                article_data = {
                    "platform": "news",
                    "title": article.get("title", "N/A"),
                    "url": article.get("url", "N/A"),
                    "text": article.get("description", "")[:500],  # Description as snippet
                    "authors": [article.get("source", {}).get("name", "N/A")],
                    "publish_date": article.get("publishedAt", "N/A"),
                    "source": article.get("source", {}).get("name", "N/A")
                }
                articles.append(article_data)
                self.all_texts.append(f"{article_data['title']} {article_data['text']}")
                time.sleep(0.2)  # Respect API rate limits
            self.data["news"] = articles
            print(f"[+] Retrieved {len(articles)} news articles")
        except Exception as e:
            print(f"[-] News search failed: {e}")
            self.data["news"] = [{"error": str(e)}]

    def analyze_sentiment(self):
        print(f"\n[*] Analyzing sentiment of {len(self.all_texts)} texts...")
        if not self.all_texts:
            print("[-] No text data to analyze")
            return

        sentiments = {"positive": 0, "negative": 0, "neutral": 0, "scores": []}
        for text in self.all_texts:
            try:
                cleaned_text = re.sub(r"http\S+", "", text)
                cleaned_text = re.sub(r"[^\w\s]", "", cleaned_text)
                blob = TextBlob(cleaned_text)
                polarity = blob.sentiment.polarity
                sentiments["scores"].append(polarity)
                if polarity > 0.1:
                    sentiments["positive"] += 1
                elif polarity < -0.1:
                    sentiments["negative"] += 1
                else:
                    sentiments["neutral"] += 1
            except Exception as e:
                print(f"[-] Sentiment analysis error: {e}")
                continue

        if sentiments["scores"]:
            sentiments["average_polarity"] = sum(sentiments["scores"]) / len(sentiments["scores"])
            sentiments["max_polarity"] = max(sentiments["scores"])
            sentiments["min_polarity"] = min(sentiments["scores"])

        total = sentiments["positive"] + sentiments["negative"] + sentiments["neutral"]
        if total > 0:
            sentiments["positive_percent"] = (sentiments["positive"] / total) * 100
            sentiments["negative_percent"] = (sentiments["negative"] / total) * 100
            sentiments["neutral_percent"] = (sentiments["neutral"] / total) * 100

        self.data["sentiment_analysis"] = sentiments

        print(f"[+] Positive: {sentiments['positive']} ({sentiments.get('positive_percent', 0):.1f}%)")
        print(f"[+] Negative: {sentiments['negative']} ({sentiments.get('negative_percent', 0):.1f}%)")
        print(f"[+] Neutral: {sentiments['neutral']} ({sentiments.get('neutral_percent', 0):.1f}%)")
        print(f"[+] Average polarity: {sentiments.get('average_polarity', 0):.3f}")

    def visualize_sentiment(self, output_file="sentiment_analysis.png"):
        try:
            sentiment_data = self.data.get("sentiment_analysis", {})
            if not sentiment_data or "positive" not in sentiment_data:
                print("[-] No sentiment data to visualize")
                return
            print(f"[*] Creating sentiment visualizations...")

            fig, axes = plt.subplots(2, 2, figsize=(14, 10))
            fig.suptitle(f'Sentiment Analysis for "{self.keyword}"', fontsize=16, fontweight="bold")

            labels = ["Positive", "Negative", "Neutral"]
            sizes = [
                sentiment_data.get("positive", 0),
                sentiment_data.get("negative", 0),
                sentiment_data.get("neutral", 0),
            ]
            colors = ["#4CAF50", "#F44336", "#FFC107"]
            explode = (0.1, 0.1, 0)

            axes[0, 0].pie(sizes, explode=explode, labels=labels, colors=colors,
                           autopct="%1.1f%%", shadow=True, startangle=90)
            axes[0, 0].set_title("Sentiment Distribution")

            axes[0, 1].bar(labels, sizes, color=colors, edgecolor="black", linewidth=1.2)
            axes[0, 1].set_title("Sentiment Counts")
            axes[0, 1].set_ylabel("Number of Posts/Articles")
            axes[0, 1].grid(axis="y", alpha=0.3)
            for i, v in enumerate(sizes):
                axes[0, 1].text(i, v + max(sizes) * 0.02, str(v), ha="center", va="bottom", fontweight="bold")

            scores = sentiment_data.get("scores", [])
            if scores:
                axes[1, 0].hist(scores, bins=30, color="#2196F3", edgecolor="black", alpha=0.7)
                axes[1, 0].axvline(sentiment_data.get("average_polarity", 0),
                                  color="red", linestyle="--", linewidth=2,
                                  label=f"Average: {sentiment_data.get('average_polarity', 0):.3f}")
                axes[1, 0].set_title("Polarity Score Distribution")
                axes[1, 0].set_xlabel("Polarity Score (-1 to 1)")
                axes[1, 0].set_ylabel("Frequency")
                axes[1, 0].legend()
                axes[1, 0].grid(alpha=0.3)

            platform_data = {}
            for platform in ["reddit", "news"]:
                if isinstance(self.data.get(platform), list):
                    count = len([x for x in self.data[platform] if not x.get("error")])
                    if count > 0:
                        platform_data[platform.capitalize()] = count
            if platform_data:
                axes[1, 1].bar(platform_data.keys(), platform_data.values(),
                               color=["#FF4500", "#0066CC"], edgecolor="black", linewidth=1.2)
                axes[1, 1].set_title("Data Sources")
                axes[1, 1].set_ylabel("Number of Items Collected")
                axes[1, 1].grid(axis="y", alpha=0.3)
                for i, (k, v) in enumerate(platform_data.items()):
                    axes[1, 1].text(i, v + max(platform_data.values()) * 0.02, str(v),
                                    ha="center", va="bottom", fontweight="bold")
            else:
                axes[1, 1].text(0.5, 0.5, "No platform data available",
                                ha="center", va="center", transform=axes[1, 1].transAxes)
                axes[1, 1].set_title("Data Sources")

            plt.tight_layout()
            plt.savefig(output_file, dpi=300, bbox_inches="tight")
            print(f"[+] Visualization saved to {output_file}")
        except Exception as e:
            print(f"[-] Visualization failed: {e}")

    def generate_report(self, output_file="osint_report.txt"):
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("=" * 70 + "\n")
                f.write("SOCIAL MEDIA OSINT ANALYSIS REPORT\n")
                f.write("=" * 70 + "\n\n")
                f.write(f"Keyword: {self.keyword}\n")
                f.write(f"Timestamp: {self.data['timestamp']}\n")
                f.write(f"Platforms: {', '.join(self.platforms)}\n\n")

                f.write("-" * 70 + "\n")
                f.write("DATA COLLECTION SUMMARY\n")
                f.write("-" * 70 + "\n")
                for platform in ["reddit", "news"]:
                    data = self.data.get(platform, [])
                    if isinstance(data, list):
                        valid_count = len([x for x in data if not x.get("error")])
                        f.write(f"{platform.capitalize()}: {valid_count} items\n")

                f.write("\n" + "-" * 70 + "\n")
                f.write("SENTIMENT ANALYSIS\n")
                f.write("-" * 70 + "\n")
                sentiment = self.data.get("sentiment_analysis", {})
                if sentiment:
                    f.write(f"Total analyzed: {len(sentiment.get('scores', []))}\n")
                    f.write(f"Positive: {sentiment.get('positive', 0)} ({sentiment.get('positive_percent', 0):.1f}%)\n")
                    f.write(f"Negative: {sentiment.get('negative', 0)} ({sentiment.get('negative_percent', 0):.1f}%)\n")
                    f.write(f"Neutral: {sentiment.get('neutral', 0)} ({sentiment.get('neutral_percent', 0):.1f}%)\n\n")
                    f.write(f"Average Polarity: {sentiment.get('average_polarity', 0):.4f}\n")
                    f.write(f"Min Polarity: {sentiment.get('min_polarity', 0):.4f}\n")
                    f.write(f"Max Polarity: {sentiment.get('max_polarity', 0):.4f}\n\n")

                if sentiment.get("positive", 0) > sentiment.get("negative", 0):
                    overall = "POSITIVE"
                elif sentiment.get("negative", 0) > sentiment.get("positive", 0):
                    overall = "NEGATIVE"
                else:
                    overall = "NEUTRAL"

                f.write(f"Overall Sentiment: {overall}\n\n")
                f.write("-" * 70 + "\n")
                f.write("INTERPRETATION\n")
                f.write("-" * 70 + "\n")

                avg_pol = sentiment.get("average_polarity", 0)
                if avg_pol > 0.3:
                    interpretation = "Highly positive public opinion"
                elif avg_pol > 0.1:
                    interpretation = "Moderately positive public opinion"
                elif avg_pol > -0.1:
                    interpretation = "Neutral or mixed public opinion"
                elif avg_pol > -0.3:
                    interpretation = "Moderately negative public opinion"
                else:
                    interpretation = "Highly negative public opinion"

                f.write(f"{interpretation}\n")
                f.write("\n" + "=" * 70 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 70 + "\n")
            print(f"[+] Report saved to {output_file}")
        except Exception as e:
            print(f"[-] Report generation failed: {e}")

    def export_json(self, output_file="osint_data.json"):
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=4, ensure_ascii=False, default=str)
            print(f"[+] JSON data saved to {output_file}")
        except Exception as e:
            print(f"[-] JSON export failed: {e}")

    def export_csv(self, output_file="osint_data.csv"):
        try:
            rows = []
            for platform in ["reddit", "news"]:
                if isinstance(self.data.get(platform), list):
                    for item in self.data[platform]:
                        if not item.get("error"):
                            row = {
                                "platform": platform,
                                "text": item.get("text", item.get("title", "N/A"))[:200],
                                "author": item.get("author", "N/A"),
                                "timestamp": item.get("created_at", item.get("publish_date", "N/A")),
                                "engagement": item.get("score", 0),
                            }
                            rows.append(row)
            if rows:
                df = pd.DataFrame(rows)
                df.to_csv(output_file, index=False, encoding="utf-8")
                print(f"[+] CSV data saved to {output_file}")
            else:
                print("[-] No data to export to CSV")
        except Exception as e:
            print(f"[-] CSV export failed: {e}")


def main():
    print("\n" + "=" * 70)
    print("SOCIAL MEDIA OSINT ANALYZER - Reddit and GNews Only")
    print("=" * 70 + "\n")

    keyword = input("Enter keyword or hashtag to analyze: ").strip()
    if not keyword:
        print("[-] No keyword provided")
        return

    osint = SocialMediaOSINT(keyword)

    print("\n[*] Starting data collection...")
    osint.search_reddit(limit=None)
    osint.search_news(max_articles=None)

    if osint.all_texts:
        osint.analyze_sentiment()
        print("\n[*] Generating reports and visualizations...")
        osint.visualize_sentiment()
        osint.generate_report()
        osint.export_json()
        osint.export_csv()
        print("\n[+] Analysis complete!")
    else:
        print("[-] No data collected. Check API credentials or internet connection.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Analysis interrupted by user")
    except Exception as e:
        print(f"\n[-] Error: {e}")
