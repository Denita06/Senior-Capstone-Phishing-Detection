Baseline Model v1 Report

Baseline Model v1.0
Date: Feb 26, 2026

Model Overview
- Model: Logistic Regression
- Feature Extraction: TF-IDF (max_features=1000, stopwords removed)
- Dataset Size: 29 emails
   - Legitimate: 18
   - Phishing: 11
- Train/Test Split: 80/20
- Random State: 42

EVALUATION RESULTS...
Classification Report
precision    recall  f1-score   support

0 (Legitimate)  0.80      1.00      0.89         4
1 (Phishing)    1.00      0.50      0.67         2

accuracy                           0.83         6
macro avg       0.90      0.75      0.78         6
weighted avg    0.87      0.83      0.81         6


Confusion Matrix:
[[4 0]
 [1 1]]


 Interpretation:
 - Overall accuracy: 83%
 - Phishing precision: 100%
 - Phishing recall: 50%
 - One phishing email was misclassified as legitimate

 Security Analysis - In cybersecurity applications, false negatives (missed phishing emails) are more critical than false positives. While precision is strong, recall must be improved in future iterations

 Baseline Limitations:
 - Small dataset (29 emails)
 - Only 6 test samples
 - No class balancing
 - No cross-validation
 - Limited feature engineering

 Next Improvements Planned:
 - Implement 5-fold cross-validation
 - Increase phishing dataset size
 - Apply class_weight='balanced'
 - Expand feature extraction