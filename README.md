# Senior CapstonL AI Phishing Email Detection System

## Overview
This project develops a machine learning system that analyzes email metadata and content to detect phishing attacks. The system extracts security-relevant features from .eml email files and applies machine learning models to classify emails as phishing or legitimate.

## Problem
Phishing attacks are one of the most common forms of social engineering used to compromise sensitive information. This project explores how machine learning can be used to automatically detect phishing indicators in email messages.

## Features
- Email parsing from `.eml` files
- Feature extraction from email headers and body
- Machine learning classification models
- Phishing risk scoring
- Email analysis tool for new emails

## Technologies
- Python
- Scikit-learn
- Pandas
- Email parsing libraries

## Machine Learning Models
- Logistic Regression
- Support Vector Machine
- Random Forest
- Ensemble Voting Classifier

## Example Output

Email Risk Score: 0.82  
Prediction: Phishing

Indicators:
- Suspicious link detected
- Urgent language detected
- Sender domain mismatch

## Project Structure


Current Model Performance (Baseline v1)
The initial Logistic Regression classifier achieved:
- Accuracy: 83%
- Phishing Precision: 100%
- Phishing Recall: 50%
These resulsts serve as a baseline prior to dataset expansion and model training

