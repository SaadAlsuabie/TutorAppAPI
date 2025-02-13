from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from api.models import (
    TutorProfile, SessionRequest, Feedback, TutorAvailability,
    Recording, Payment, Message, Notification
)
from api.serializers import (
    UserRegisterSerializer, UserLoginSerializer, TutorProfileSerializer,
    SessionRequestSerializer, FeedbackSerializer, TutorAvailabilitySerializer,
    RecordingSerializer, PaymentSerializer, MessageSerializer, NotificationSerializer
)
from django.db.models import Q

User = get_user_model()

# Authentication Views

class RegisterAPI(APIView):
    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            role = serializer.validated_data.get('role')

            # Check if the user already exists
            if User.objects.filter(email=email).exists():
                return Response(
                    {"error": "A user with this email already has an active account."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate email domain based on role
            if role == 'student' and not email.endswith('@student.example.com'):
                return Response(
                    {"error": "Student email must end with @student.example.com."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            elif role == 'tutor' and not email.endswith('@tutor.example.com'):
                return Response(
                    {"error": "Tutor email must end with @tutor.example.com."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Save the user if all checks pass
            user = serializer.save()
            return Response(
                {"message": "User registered successfully", "user_id": user.id},
                status=status.HTTP_201_CREATED
            )

        # Return serializer errors if validation fails
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class LoginAPI(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data, context={'request': request})

        if serializer.is_valid():
            try:
                user = serializer.validated_data['user']  # Access the authenticated user
                refresh = RefreshToken.for_user(user)
                return Response({
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }, status=status.HTTP_200_OK)
            except KeyError:
                return Response({"error": "User not found in validated data"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Student Path Views
class BrowseTutorsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        course_id = request.query_params.get('course_id')
        tutors = TutorProfile.objects.filter(tutorcourse__course_id=course_id)
        serializer = TutorProfileSerializer(tutors, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class RequestSessionAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = SessionRequestSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(student=request.user)
            return Response({"message": "Session request sent", "request_id": serializer.data['id']}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LeaveFeedbackAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = FeedbackSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(from_user=request.user)
            return Response({"message": "Feedback submitted", "feedback_id": serializer.data['id']}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Tutor Path Views
class SetAvailabilityAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = TutorAvailabilitySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(tutor=request.user)
            return Response({"message": "Availability set", "availability_id": serializer.data['id']}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AcceptDeclineSessionAPI(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, request_id):
        try:
            session_request = SessionRequest.objects.get(id=request_id, tutor=request.user)
        except SessionRequest.DoesNotExist:
            return Response({"error": "Session request not found"}, status=status.HTTP_404_NOT_FOUND)

        status_action = request.data.get('status')
        if status_action not in ['accepted', 'declined']:
            return Response({"error": "Invalid status"}, status=status.HTTP_400_BAD_REQUEST)

        session_request.status = status_action
        if status_action == 'declined':
            session_request.decline_reason = request.data.get('decline_reason', '')
        session_request.save()

        return Response({"message": f"Session request {status_action}"}, status=status.HTTP_200_OK)

class UploadRecordingAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = RecordingSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(tutor=request.user)
            return Response({"message": "Recording uploaded", "recording_id": serializer.data['id']}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Payment Views
class MakePaymentAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PaymentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Payment successful", "payment_id": serializer.data['id']}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Messaging Views
class SendMessageAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(sender=request.user)
            return Response({"message": "Message sent", "message_id": serializer.data['id']}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class GetMessagesAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_id = request.user.id
        messages = Message.objects.filter(Q(sender_id=user_id) | Q(receiver_id=user_id))
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

# Notification Views
class GetNotificationsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_id = request.user.id
        notifications = Notification.objects.filter(user_id=user_id)
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

# Search Views
class SearchTutorsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        query = request.query_params.get('query', '')
        tutors = TutorProfile.objects.filter(
            Q(user__first_name__icontains=query) |
            Q(user__last_name__icontains=query) |
            Q(bio__icontains=query)
        )
        serializer = TutorProfileSerializer(tutors, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)