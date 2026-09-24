from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from analyzer.parser import analyze_header
from django.views import View


# Create your views here.
class LoginView(View):
    def get(self, request):
        return render(request, 'analyzer/login.html')

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = None
        try:
            user = authenticate(request, username=username, password=password)
        except:
            login_validation = False

        login_validation = False if user is None else True

        context = {'login_validation': login_validation}
        if login_validation:
            login(request, user)
            return redirect('home_view')
        else:
            return render(request, 'analyzer/login.html', context)

class LogoutView(View):
    def get(self, request):
        logout(request)
        return redirect('/')

class HomeView(View):
    def get(self, request):
        if not request.user.is_authenticated:
            return redirect('login')
        return render(request, 'analyzer/analyzer.html')

    def post(self, request):
        if not request.user.is_authenticated:
            return redirect('login')
        header = request.POST.get('header')
        results = analyze_header(header)
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

        try:
            user = User.objects.create_user(username=username, email=email, password=password)
            user.save()
        except:
            context = {'signup_validation': False}
            return render(request, 'analyzer/signup.html', context)

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home_view')
        else:
            context = {'signup_validation': False}
            return render(request, 'analyzer/signup.html', context)
    