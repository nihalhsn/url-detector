import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pickle
import re
from urllib.parse import urlparse
import tldextract
from datetime import datetime
import math
from collections import Counter

# Feature extraction function (same as in app.py)
def extract_features(url):
    features = {}
    try:
        parsed = urlparse(url)
        extracted = tldextract.extract(url)

        features['url_length'] = len(url)
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        features['path_length'] = len(parsed.path)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['has_at_symbol'] = 1 if '@' in url else 0
        features['has_ip_address'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain) else 0

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.buzz', '.click', '.work', '.date', '.racing', '.loan', '.download', '.men', '.gdn']
        features['suspicious_tld'] = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0

        keywords = ['login', 'verify', 'secure', 'account', 'password', 'bank', 'update', 'confirm', 'security', 'verify', 'authentication', 'wallet', 'crypto', 'bitcoin']
        features['has_suspicious_keywords'] = sum(1 for kw in keywords if kw in url.lower())

        # Calculate entropy
        if len(url) > 0:
            prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
            features['entropy_score'] = -sum(p * math.log(p) / math.log(2) for p in prob if p > 0)
        else:
            features['entropy_score'] = 0

        # Check brand in subdomain
        brands = ['paypal', 'google', 'amazon', 'apple', 'microsoft', 'facebook', 'netflix', 'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa', 'mastercard']
        subdomain = extracted.subdomain.lower()
        features['brand_in_subdomain'] = sum(1 for brand in brands if brand in subdomain)

        # Domain age placeholder (will be -1 for training)
        features['domain_age_days'] = -1

    except Exception as e:
        print(f"Error extracting features from {url}: {e}")
        for name in ['url_length', 'has_https', 'domain_age_days', 'has_at_symbol',
                     'subdomain_count', 'path_length', 'num_dots', 'num_hyphens',
                     'has_ip_address', 'suspicious_tld', 'brand_in_subdomain',
                     'has_suspicious_keywords', 'entropy_score']:
            features[name] = 0
    
    return features

def prepare_dataset():
    """
    Create dataset with sample phishing and legitimate URLs
    In production, replace with your own dataset
    """
    
    # Legitimate URLs (label: 0)
    legitimate_urls = [
        "https://www.google.com",
        "https://www.amazon.com",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.github.com",
        "https://stackoverflow.com",
        "https://www.wikipedia.org",
        "https://www.linkedin.com",
        "https://www.reddit.com",
        "https://www.nytimes.com",
        "https://www.bbc.com",
        "https://www.cnn.com",
        "https://www.paypal.com",
        "https://www.chase.com",
        "https://www.bankofamerica.com",
        "https://www.wellsfargo.com",
        "https://www.citibank.com",
        "https://www.amazon.co.uk",
        "https://www.amazon.de",
        "https://www.google.co.uk",
        "https://www.youtube.com",
        "https://www.twitter.com",
        "https://www.facebook.com",
        "https://www.instagram.com",
        "https://www.netflix.com",
        "https://www.spotify.com",
        "https://www.dropbox.com",
        "https://www.slack.com",
        "https://www.zoom.us",
        "https://www.shopify.com",
        "https://www.etsy.com",
        "https://www.ebay.com",
        "https://www.target.com",
        "https://www.walmart.com",
        "https://www.bestbuy.com",
        "https://www.homedepot.com",
        "https://www.lowes.com",
        "https://www.costco.com",
        "https://www.samsclub.com",
        "https://www.macys.com",
        "https://www.nordstrom.com",
        "https://www.zappos.com",
        "https://www.booking.com",
        "https://www.airbnb.com",
        "https://www.uber.com",
        "https://www.lyft.com",
        "https://www.doordash.com",
        "https://www.grubhub.com",
        "https://www.postmates.com",
        "https://www.ubereats.com",
    ]
    
    # Phishing URLs (label: 1) - These are examples of suspicious patterns
    phishing_urls = [
        "http://paypa1.com/login/verify",
        "http://amaz0n-security.com/update-account",
        "https://google-security-verify.tk/login",
        "http://facebook-confirm.ml/verify",
        "https://appleid-verify.xyz/authenticate",
        "http://netflix-billing.ga/update-payment",
        "https://chase-online-security.tk/login",
        "http://wellsfargo-confirm.cf/verify",
        "https://bankofamerica-update.top/login",
        "http://citibank-secure.xyz/verify",
        "https://amazon-login-verify.work/signin",
        "http://microsoft-account-secure.date/verify",
        "https://apple-icloud-confirm.racing/authenticate",
        "http://paypal-resolution-center.loan/verify",
        "https://google-drive-download.download/secure",
        "http://facebook-security-check.men/login",
        "https://instagram-verify-account.gdn/confirm",
        "http://twitter-support-center.click/verify",
        "https://linkedin-security-update.buzz/login",
        "http://amazon-prime-verify.xyz/update",
        "https://netflix-account-suspend.tk/reactivate",
        "http://spotify-premium-secure.ml/verify",
        "https://dropbox-shared-file.ga/download",
        "http://zoom-meeting-invite.work/join",
        "https://shopify-order-confirm.top/verify",
        "http://etsy-account-security.date/login",
        "https://ebay-buyer-protection.racing/verify",
        "http://target-gift-card.loan/claim",
        "https://walmart-order-update.download/track",
        "http://bestbuy-deals-today.men/verify",
        "https://homedepot-survey-secure.gdn/reward",
        "http://lowes-coupon-code.click/claim",
        "https://costco-membership-renew.tk/update",
        "http://samsclub-account-verify.xyz/login",
        "https://macys-order-tracking.buzz/track",
        "http://nordstrom-security-check.work/verify",
        "https://zappos-order-confirm.date/verify",
        "http://booking-confirmation.racing/secure",
        "https://airbnb-payment-update.loan/verify",
        "http://uber-account-suspend.top/reactivate",
        "https://lyft-payment-issue.ml/update",
        "http://doordash-refund-secure.ga/claim",
        "https://grubhub-order-cancel.tk/verify",
        "http://postmates-delivery-issue.xyz/track",
        "https://ubereats-payment-failed.work/update",
        # Additional phishing patterns
        "http://secure-paypal.com.fakewebsite.com/login",
        "https://amazon.com.security-verify.tk/signin",
        "http://bankofamerica.com.confirmation.ml/verify",
        "https://google.com.accounts.verify.xyz/login",
        "http://apple.com.id.verify.ga/authenticate",
        "https://microsoft.com.security.update.top/verify",
        "http://netflix.com.billing.issue.cf/update",
        "https://chase.com.online.banking.secure.tk/login",
        "http://wellsfargo.com.account.verify.click/confirm",
        "https://facebook.com.security.alert.work/verify",
    ]
    
    # Create dataset
    data = []
    
    print("Extracting features from legitimate URLs...")
    for url in legitimate_urls:
        features = extract_features(url)
        features['label'] = 0  # 0 = legitimate
        data.append(features)
    
    print("Extracting features from phishing URLs...")
    for url in phishing_urls:
        features = extract_features(url)
        features['label'] = 1  # 1 = phishing
        data.append(features)
    
    df = pd.DataFrame(data)
    return df

def train_model():
    """Train and save the phishing detection model"""
    
    # Prepare dataset
    df = prepare_dataset()
    
    print(f"\nDataset shape: {df.shape}")
    print(f"Legitimate samples: {len(df[df['label'] == 0])}")
    print(f"Phishing samples: {len(df[df['label'] == 1])}")
    
    # Features and target
    feature_names = [
        'url_length', 'has_https', 'domain_age_days', 'has_at_symbol',
        'subdomain_count', 'path_length', 'num_dots', 'num_hyphens',
        'has_ip_address', 'suspicious_tld', 'brand_in_subdomain',
        'has_suspicious_keywords', 'entropy_score'
    ]
    
    X = df[feature_names]
    y = df['label']
    
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")
    
    # Train Random Forest
    print("\nTraining Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=200,      # More trees for better accuracy
        max_depth=10,            # Prevent overfitting
        min_samples_split=5,     # Minimum samples to split a node
        min_samples_leaf=2,      # Minimum samples at leaf node
        random_state=42,
        n_jobs=-1                # Use all CPU cores
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = model.predict(X_test)
    
    print("\n" + "="*50)
    print("MODEL EVALUATION")
    print("="*50)
    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Feature importance
    print("\n" + "="*50)
    print("FEATURE IMPORTANCE")
    print("="*50)
    importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    for _, row in importance_df.iterrows():
        print(f"{row['feature']:30s}: {row['importance']:.4f}")
    
    # Save model
    model_data = {
        'model': model,
        'feature_names': feature_names,
        'training_date': datetime.now().isoformat(),
        'samples': len(df),
        'accuracy': accuracy_score(y_test, y_pred)
    }
    
    with open('phishing_model.pkl', 'wb') as f:
        pickle.dump(model_data, f)
    
    print("\n" + "="*50)
    print("Model saved to 'phishing_model.pkl'")
    print("="*50)
    
    return model, feature_names

def test_model():
    """Test the trained model with sample URLs"""
    
    # Load model
    with open('phishing_model.pkl', 'rb') as f:
        model_data = pickle.load(f)
    
    model = model_data['model']
    feature_names = model_data['feature_names']
    
    test_urls = [
        "https://www.google.com",                           # Should be safe
        "https://www.amazon.com",                           # Should be safe
        "http://paypa1.com/login/verify",                   # Should be phishing
        "https://google-security-verify.tk/login",          # Should be phishing
        "https://github.com",                               # Should be safe
        "http://amaz0n-security.com/update-account",        # Should be phishing
    ]
    
    print("\n" + "="*50)
    print("TESTING MODEL")
    print("="*50)
    
    for url in test_urls:
        features = extract_features(url)
        X = np.array([features[name] for name in feature_names]).reshape(1, -1)
        
        prediction = model.predict(X)[0]
        probability = model.predict_proba(X)[0]
        
        result = "PHISHING" if prediction == 1 else "LEGITIMATE"
        confidence = max(probability)
        
        print(f"\nURL: {url}")
        print(f"Result: {result} (confidence: {confidence:.2%})")

if __name__ == '__main__':
    # Train model
    model, features = train_model()
    
    # Test model
    test_model()