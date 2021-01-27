# Implementation Engineer Interview Questions Response
## SECTION B QUESTION 1
#### under views.py where functionalities and HttpResponse is used to enable render on a page
```
{
from django.db import connection
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.forms import UserCreationForm
from .forms import CreateUserForm
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required

def register(request):

    form = CreateUserForm()
    if request.method == 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid():
            form.save()
            user = form.cleaned_data.get('username')
            messages.success(request, 'Account was created for' + user)

            return redirect('login')

    context = {'form': form}
    return render(request, 'pages/register.html', context)

def login_func(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('index')
        else:
            messages.info(request, 'username OR password is incorrect')
    context = {}
    return render(request, 'pages/login.html', context)

def logoutUser(request):
    logout(request)
    return redirect('login')

@login_required(login_url='login')

}
```
#### Under urls.py to show the url show that one can view
``` python
from django.urls import path

from . import views

urlpatterns = [
   path('index', views.index, name='index'),
   path('', views.login_func, name='login'),
   path('logout', views.logoutUser, name='logout'),
   path('register', views.register, name='register'),
]
```

#### Using HTML create LOGIN.HTML to view on User Interface 
```
</head>
<body>
	<div class="container h-100">
		<div class="d-flex justify-content-center h-100">
			<div class="user_card">
				<div class="d-flex justify-content-center">


					<h3 id="form-title">LOGIN</h3>
				</div>
				<div class="d-flex justify-content-center form_container">
					<form method="POST" action="">
                        {% csrf_token %}
						<div class="input-group mb-3">
							<div class="input-group-append">
								<span class="input-group-text"><i class="fas fa-user"></i></span>
							</div>
							<input type="text" name="username" placeholder="Username..." class="form-control">
						</div>
						<div class="input-group mb-2">
							<div class="input-group-append">
								<span class="input-group-text"><i class="fas fa-key"></i></span>
							</div>
								<input type="password" name="password" placeholder="Password..." class="form-control" >
						</div>

							<div class="d-flex justify-content-center mt-3 login_container">
				 				<input class="btn login_btn" type="submit" value="Login">
				   			</div>
					</form>

				</div>
                {% for message in messages %}
                    <p id="messages">{{ message }}</p>
                {% endfor %}
				<div class="mt-4">
					<div class="d-flex justify-content-center links">
						Don't have an account? <a href="/register" class="ml-2">Sign Up</a>
					</div>

				</div>
			</div>
		</div>
	</div>
</body>
```
## SUCCESS PAGE 
#### views.py to enable viewing for a page after logging in
```
{
def index(request):
    return render(request, 'pages/index.html')

@login_required(login_url='login')

#lndex.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Home</title>
    <style>
        hello-msg {
            font-size: 18px;
            color: #cccccc;
            margin-right: 20px;
        }
        body {
          margin: 0;
        }
        ul {
          list-style-type: none;
          margin: 0;
          padding: 0;
          width: 25%;
          background-color: #808080;
          position: fixed;
          height: 100%;
          overflow: auto;
        }
        li a {
          display: block;
          color: #cccccc;
          padding: 8px 16px;
          text-decoration: none;
        }
        li a.active {
          color: white;
        }
        li a:hover:not(.active) {
          background-color: #f7ba5b;
          color: white;
        }
    </style>
</head>
<body>
    <nav>
        <ul>
            <span style="color: #cccccc" id ="hello-msg">Hello, {{request.user}} &nbsp  </span>
            <span ><a href="/logout">Logout</a></span>
            <li><a href="#">Home</a></li>
        </ul>
    </nav>
</body>
</html>
}
```
## SECTION A QUESTION 1
#### DJANGO REST FRAMEWORK IS ONE OF FRAMEWORKS I KNOW OF 
`Install using pip `

#### Add `rest_framework` to INSTALLED_APPS setting
```
INSTALLED_APPS = [
    'rest_framework',
]
```
#### Add REST framework's login and logout views in urls.py
```
urlpatterns = [
    path('api-auth/', include('rest_framework.urls'))
]
```
#### Add `REST_FRAMEWORK` IN `settings.py` module:
**Giving permissions to authorized users and read only to the unauthorized users**
```
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.DjangoModelPermissionsOrAnonReadOnly'
    ]
}
```
## SECTION A QUESTION 3
#### *Salt*
#### *Python bcrypt*

```
import bcrypt

passwd = b's$cret12'

#Generation of salt variable with the gensalt() function 
salt = bcrypt.gensalt()

Creation of a hashed function 
hashed = bcrypt.hashpw(passwd, salt)

if bcrypt.checkpw(passwd, hashed):
    print("match")
else:
    print("does not match")
```


