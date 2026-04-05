# Senior Capstone: AI Phishing Email Detection System

# Senior Capstone: AI Phishing Email Detection System

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Sklearn-orange)
![Status](https://img.shields.io/badge/Status-Active%20Development-green)
![Dataset](https://img.shields.io/badge/Dataset-Multi--Source-blueviolet)
![Capstone](https://img.shields.io/badge/Project-Senior%20Capstone-red)

## Overview
This project develops a machine learning system that analyzes email metadata and content to detect phishing attacks. The system extracts security-relevant features from `.eml` email files and applies machine learning models to classify emails as phishing or legitimate.

---

## Problem
Phishing attacks are one of the most common forms of social engineering used to compromise sensitive information. This project explores how machine learning can be used to automatically detect phishing indicators in email messages.

---

## Features
- Email parsing from `.eml` files
- Feature extraction from email headers and body
- Multi-source dataset integration
- Machine learning classification models
- Phishing risk scoring
- Email analysis tool for new emails

---

## Technologies
- Python
- Pandas
- Scikit-learn
- NumPy
- Email parsing libraries

---

## Machine Learning Models
- Logistic Regression
- Support Vector Machine (SVM)
- Random Forest
- Ensemble Voting Classifier

---

## Dataset Sources

This project uses multiple real-world phishing and legitimate email datasets:

### 📧 Enron Email Dataset
- Source: https://www.cs.cmu.edu/~enron/
- Description: Large corpus of real corporate emails used for legitimate email examples.

---

### 🎣 Nazario Phishing Corpus
- Source: https://monkey.org/~jose/wiki/doku.php?id=PhishingCorpus
- Description: Early curated dataset of phishing emails used in academic research.

---

### 📊 Kaggle Email Spam Dataset
- Source: https://www.kaggle.com/datasets
- Description: Collection of labeled spam and ham emails used for classification tasks.

---

### ⚠️ CEAS 2008 Spam Dataset
- Source: https://plg.uwaterloo.ca/~gvcormac/ceascorpus/
- Description: Benchmark dataset for spam and phishing email detection research.

---

### 💰 Nigerian Fraud Email Dataset
- Source: https://www.kaggle.com/datasets
- Description: Contains scam and fraud-related email messages.

---

### 📩 SpamAssassin Public Corpus
- Source: https://spamassassin.apache.org/old/publiccorpus/
- Description: Widely used dataset containing spam and legitimate email messages.

---

## Example Output

Email Risk Score: 0.82  
Prediction: Phishing  

Indicators:
- Suspicious link detected  
- Urgent language detected  
- Sender domain mismatch  

---

## Current Model Performance (Baseline v1)

The initial Logistic Regression classifier achieved:

- Accuracy: 83%
- Phishing Precision: 100%
- Phishing Recall: 50%

These results serve as a baseline prior to dataset expansion and advanced model training.

---

## Project Structure
