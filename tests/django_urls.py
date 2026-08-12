from django.urls import path
from django.http import HttpResponse, JsonResponse


def echo(request):
    return HttpResponse(request.body, content_type="text/plain")


def plain(request):
    return JsonResponse({"msg": "not encrypted"})


urlpatterns = [
    path("echo", echo),
    path("plain", plain),
]