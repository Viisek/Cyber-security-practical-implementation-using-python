

def spam_filter(email_text):
    # Keywords commonly found in spam emails
    spam_keywords = ['offer', 'discount', 'free', 'prize', 'limited', 'urgent', 'money', 'click', 'order', 'buy']

    # Count occurrences of spam keywords in the email text
    spam_count = sum(email_text.lower().count(keyword) for keyword in spam_keywords)

    # Threshold for considering an email as spam (you can adjust this threshold as needed)
    spam_threshold = 3

    # Determine if the email is spam or not based on the spam count
    if spam_count >= spam_threshold:
        return True # Spam
    else:
        return False # Not spam


# Example usage
if __name__ == "__main__":
    # Example email texts
    email1 = "Get a limited time offer! Click here to win a free prize!"
    email2 = "Hi there, how are you doing?"

    # Check if the emails are spam or not
    if spam_filter(email1):
        print("Email 1 is spam.")
    else:
        print("Email 1 is not spam.")

    if spam_filter(email2):
        print("Email 2 is spam.")
    else:
        print("Email 2 is not spam.")