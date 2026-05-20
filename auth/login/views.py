from django.shortcuts import render
from rest_framework import generics, status
from .models import User
from .serializers import UserSerializer
from rest_framework.response import Response
from rest_framework.views import APIView


class UserListCreate(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()  # saves plain-text password
            return Response(
                {"message": "User registered successfully", "user": serializer.data},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class LoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response(
                {"error": "Invalid username or password"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Plain password comparison (no hashing)
        if password == user.password:
            return Response(
                {"message": "Login successful"},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"error": "Invalid username or password"},
                status=status.HTTP_400_BAD_REQUEST
            )

class SecurityAnalysisView(APIView):
    def post(self, request):
        task = request.data.get("task")
        payload = request.data.get("data", {})

        if not task:
            return Response({"error": "Task parameter is required"}, status=status.HTTP_400_BAD_REQUEST)

        from .security_engine import SecurityEngine

        try:
            if task == "risk_classifier":
                ip = payload.get("ip", "")
                device = payload.get("device", "")
                location = payload.get("location", "")
                time = payload.get("time", "")
                failed_attempts = payload.get("failed_attempts", 0)
                previous_locations = payload.get("previous_locations", [])
                
                result = SecurityEngine.classify_risk(ip, device, location, time, failed_attempts, previous_locations)
                return Response(result, status=status.HTTP_200_OK)

            elif task == "suspicious_activity":
                logs = payload.get("logs", "")
                result = SecurityEngine.detect_suspicious_activity(logs)
                return Response(result, status=status.HTTP_200_OK)

            elif task == "session_conflict":
                sessions = payload.get("sessions", "")
                result = SecurityEngine.resolve_session_conflict(sessions)
                return Response(result, status=status.HTTP_200_OK)

            elif task == "log_summarizer":
                logs = payload.get("logs", "")
                result = SecurityEngine.summarize_auth_logs(logs)
                return Response(result, status=status.HTTP_200_OK)

            elif task == "brute_force":
                login_attempts = payload.get("login_attempts", "")
                result = SecurityEngine.detect_brute_force(login_attempts)
                return Response(result, status=status.HTTP_200_OK)

            else:
                return Response({"error": f"Unknown task: {task}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    