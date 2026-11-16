import difflib
import re
from html import unescape
from html.parser import HTMLParser

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.utils import timezone
from .models import LoginAttempt, Email
from django.shortcuts import render, redirect, get_object_or_404
from analyzer.parser import analyze_header, analyze_body, assess_spam
from analyzer.spoofed_chars import find_spoof_characters
from django.views import View
from datetime import timedelta
from email import message_from_bytes, policy
from django.db.models import Q
from analyzer.geolocation import add_location_and_network_info


# Create your views here.
class LoginView(View):
    def get(self, request):
        return render(request, 'analyzer/login.html')

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        attempt, created = LoginAttempt.objects.get_or_create(
            username=username
        )
        context = {}

        now = timezone.now()

        if attempt.lock_time is not None:
            unlock_time = attempt.lock_time + timedelta(minutes=1)

            if now < unlock_time:
                seconds_remaining = int(
                    (unlock_time - now).total_seconds()
                )

                context = {
                    'login_validation': False,
                    'locked': True,
                    'seconds_remaining': seconds_remaining,
                }

                return render(
                    request,
                    'analyzer/login.html',
                    context,
                    status=429,
                )

            attempt.failures = 0
            attempt.lock_time = None
            attempt.save(update_fields=['failures', 'lock_time'])

        user = authenticate(
            request,
            username=username,
            password=password,
        )

        if user is not None:
            attempt.failures = 0
            attempt.lock_time = None
            attempt.save(update_fields=['failures', 'lock_time'])

            login(request, user)
            return redirect('welcome')

        attempt.failures += 1

        if attempt.failures >= 3:
            attempt.lock_time = now

        attempt.save(update_fields=['failures', 'lock_time'])

        context = {
            'login_validation': False,
            'locked': attempt.lock_time is not None,
        }

        return render(request, 'analyzer/login.html', context)



class LogoutView(View):
    def get(self, request):
        logout(request)
        return redirect('/')

class HomeView(View):
    def get(self, request):
        if not request.user.is_authenticated:
            return redirect('login')
        else:
            context = {'is_authenticated': True}
        return render(request, 'analyzer/analyzer.html', context)

    def post(self, request):
        if not request.user.is_authenticated:
            return redirect('login')
        context = {'is_authenticated': True}
        header = request.POST.get('header')
        results = analyze_header(header)

        # Add location and ASN(who runs the server) info to each Received
        results["received"] = add_location_and_network_info(
            results["received"]
        )

        context = {'submitted': True,
                   'header_preview': header[:100],
                   'results': results
                   }
        return render(request, 'analyzer/analyzer.html', context)

class SignupView(View):
    def get(self, request):
        return render(request, 'analyzer/signup.html')

    def post(self, request):
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if not username or not email or not password:
            context = {'signup_entered': False}
            return render(request, 'analyzer/signup.html', context)

        context = {'is_authenticated': False, 'signup_entered': True, 'unique_username': True, 'unique_email': True, 'same_password': True}

        username_exists = User.objects.filter(username=username).exists()
        if username_exists:
            context['unique_username'] = False
            return render(request, 'analyzer/signup.html', context)

        email_exists = User.objects.filter(email=email).exists()
        if email_exists:
            context['unique_email'] = False
            return render(request, 'analyzer/signup.html', context)

        if password != confirm_password:
            context['same_password'] = False
            return render(request, 'analyzer/signup.html', context)

        user = User.objects.create_user(username=username, email=email, password=password)

        user = authenticate(request, username=username, password=password)
        if user is not None:
            return redirect('login')
        else:
            context = {'signup_validation': False}
            return render(request, 'analyzer/signup.html', context)

class ResultsView(View):
    def get(self, request):
        return render(request, 'analyzer/results.html')

    def post(self, request):
        if not request.user.is_authenticated:
            return redirect('login')
        if "file" in request.FILES:
            # Read the uploaded .eml file
            raw_bytes = request.FILES["file"].read()
            raw_text = raw_bytes.decode("utf-8", errors="ignore")
            header = raw_text.replace("\r\n", "\n").partition("\n\n")[0]
            msg = message_from_bytes(raw_bytes, policy=policy.default)
            body_part = msg.get_body(preferencelist=("plain", "html"))
            body = body_part.get_content() if body_part else ""
        else:
            # Get the header and body from the form
            header = request.POST.get("header")
            body = request.POST.get("body")
        results = analyze_header(header)
        results["received"] = add_location_and_network_info(results["received"])
        body_results = analyze_body(body)
        spoof_flags = find_spoof_characters(results["from"] or "")
        spam_result = assess_spam(
                        results,
                        body,
                        body_results,
                        spoof_flags,
        )

        new_email = Email(body=body, header=header, user=request.user)

        new_email.status = (
                'spam/scam'
                if spam_result['potential_spam']
                else 'safe'
                )
        if spoof_flags:
            new_email.status = 'unsafe'
        new_email.save()

        context = {
            'is_authenticated': True,
            'submitted': True,
            'header_preview': header[:100],
            'results': results,
            'body_results': body_results,
            'spoof_flags': spoof_flags,
            'spam_result': spam_result,
            'email': new_email,
        }

        return render(request, 'analyzer/results.html', context)

class EmailResultsView(View):
    def get(self, request, email_id):
        if not request.user.is_authenticated:
            return redirect('login')
        email = get_object_or_404(Email, id=email_id, user=request.user)
        results = analyze_header(email.header)
        results["received"] = add_location_and_network_info(results["received"])
        body_results = analyze_body(email.body)
        spoof_flags = find_spoof_characters(results["from"] or "")
        
        spam_result = assess_spam(
                    results,
                    email.body,
                    body_results,
                    spoof_flags,
        )
        new_status = 'spam/scam' if spam_result['potential_spam'] else 'safe'
        
        if spoof_flags:
            new_status='unsafe'
        
        if email.status != new_status:
            email.status = new_status
            email.save(update_fields=['status'])

        context = {
            'is_authenticated': True,
            'submitted': True,
            'header_preview': email.header[:100],
            'results': results,
            'body_results': body_results,
            'spoof_flags': spoof_flags,
            'spam_result': spam_result,
            'email': email,
        }
        return render(request, 'analyzer/results.html', context)

class PastEmailsAnalyzedView(View):
    def get(self, request):
        if not request.user.is_authenticated:
            return redirect('login')
        past_emails = Email.objects.filter(user=request.user)
        sort_by = request.GET.get('sort', '-id').strip()
        if sort_by == 'id':
            past_emails = past_emails.order_by('id')
        elif sort_by == 'status':
            past_emails = past_emails.order_by('status', '-id')
        else:
            past_emails = past_emails.order_by('-id')
        status = request.GET.get('status', '').strip()
        query = request.GET.get('q', '').strip()
        if status:
            past_emails = past_emails.filter(status=status)
        if query:
            past_emails = past_emails.filter(
                Q(header__icontains=query) | Q(body__icontains=query)
            )
        context = {
           'is_authenticated': True,
           'past_emails': past_emails,
           'selected_status': status,
           'search_query': query,
           'selected_sort': sort_by,
        }
        return render(request, 'analyzer/past_emails.html', context)

class DeleteEmailAnalyzedView(View):
    def get(self, request):
        if not request.user.is_authenticated:
            return redirect('login')

    def post(self, request, email_id):
        if not request.user.is_authenticated:
            return redirect('login')
        email = get_object_or_404(Email, id=email_id, user=request.user)
        email.delete()
        return redirect('past_emails')

class WelcomePageView(View):
    def get(self, request):
        if not request.user.is_authenticated:
            return redirect('login')
        context = {'is_authenticated': True}
        return render(request, 'analyzer/welcome.html', context)

class ResetPasswordView(View):
    def get(self, request):
        return render(request, 'analyzer/reset_password.html')

    def post(self, request):
        username = request.POST.get('username')
        email = request.POST.get('email')
        new_password = request.POST.get('new_password')
        confirm_new_password = request.POST.get('confirm_new_password')

        context = {'is_authenticated': False, 'reset_entered': True, 'username_exists': User.objects.filter(username=username).exists(), 'email_exists': User.objects.filter(email=email).exists(),'user_exists': False, 'same_password': True}

        if not new_password or (new_password != confirm_new_password):
            context['same_password'] = False
            return render(request, 'analyzer/reset_password.html', context)

        user = User.objects.filter(username=username, email=email).first()

        if user:
            context['user_exists'] = True
            user.set_password(new_password)
            user.save()
            return redirect('login')
        else:
            context = {'reset_entered': True, 'username_exists': User.objects.filter(username=username), 'email_exists': User.objects.filter(email=email), 'same_password': False}
            return render(request, 'analyzer/reset_password.html', context)


@login_required
def compare_emails(request):
    if not request.user.is_authenticated:
        return redirect('login')
    if request.method != "POST":
        return redirect('past_emails')
    email_ids = request.POST.getlist('email_ids')

    if len(set(email_ids)) != 2:
        messages.error(request, 'Exactly two emails can be compared.')
        return redirect('past_emails')

    emails = Email.objects.filter(id__in=email_ids, user=request.user)

    if emails.count() != 2:
        messages.error(request, 'One or more emails could not be found')
        return redirect('past_emails')

    email1 = emails.order_by('-id')[0]
    email2 = emails.order_by('-id')[1]

    email1_lines, email2_lines = list(compare_email_text(email1, email2))
    ratio = email_similarity(email1, email2)

    return render(request, 'analyzer/compare_emails.html', {'is_authenticated': True, 'emails': emails, 'ratio': ratio, 'email1_lines': email1_lines, 'email2_lines': email2_lines})

def compare_email_text(email1, email2):
    body1 = clean_email_body(email1.body).split(' ')
    body2 = clean_email_body(email2.body).split(' ')

    diff = list(difflib.ndiff(body1, body2))

    email1_lines= []
    email2_lines= []

    for line in diff:
        if line.startswith('+'):
            email2_lines.append({'text': line[2:], 'type': 'added'})
        elif line.startswith('-'):
            email1_lines.append({'text': line[2:], 'type': 'removed'})
        elif line.startswith(' '):
            text = line[2:]
            email1_lines.append({'text': text, 'type': 'unchanged'})
            email2_lines.append({'text': text, 'type': 'unchanged'})

    return email1_lines, email2_lines

def email_similarity(email1, email2):
    body1 = clean_email_body(email1.body)
    body2 = clean_email_body(email2.body)
    return round(difflib.SequenceMatcher(None, body1, body2).ratio() * 100, 2)

class EmailHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text = []
        self.skip_tags = {'style', 'script', 'head'}
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.skip_tags:
            self.skip_depth += 1

    def handle_endtag(self, tag):
        if tag in self.skip_tags and self.skip_depth > 0:
            self.skip_depth -= 1

    def handle_data(self, data):
        if self.skip_depth == 0:
            self.text.append(data)

    def get_text(self):
        return ' '.join(self.text)

def clean_email_body(body):
    # Remove HTML
    body = re.sub(r'@media[^{]*\{(?:[^{}]|\{[^{}]*\})*\}','',body, flags=re.IGNORECASE)
    body = re.sub(r'(?is)<(style|script|head)\b[^>]*>.*?</\1\s*>', '', body)

    parser = EmailHTMLParser()
    parser.feed(body)
    text = unescape(parser.get_text())
    # Remove unicode
    text = re.sub(r'[\u200b-\u200f\u2060\ufeff\u00ad]', '', text)
    # Add and normalize whitespace
    text = re.sub(r'(?<=[a-zA-Z0-9])(?=[A-Z])', '', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

def header_help_view(request):
    return render(request, "analyzer/header_tutorial.html")