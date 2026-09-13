from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
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
