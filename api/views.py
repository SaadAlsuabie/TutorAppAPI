from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from api.models import (
    User, TutorProfile, SessionRequest, Feedback, TutorAvailability,
    Recording, Payment, Message, Notification, StudentProfile, TutorProfile,
    Faculty, Major, SessionType
)
from api.serializers import (
    UserRegisterSerializer, UserLoginSerializer, TutorProfileSerializer,
    SessionRequestSerializer, FeedbackSerializer, TutorAvailabilitySerializer,
    RecordingSerializer, PaymentSerializer, MessageSerializer, NotificationSerializer
)
from django.db.models import Q
from api.permissions import AllowAny

User = get_user_model()

# Authentication Views

class RegisterAPI(APIView):
    authentication_classes = []
    permission_classes = [AllowAny] 
    """
        checking first if the user already exist
    """
    def post(self, request):
        try:
            request_data: dict = request.data
            role = request_data.get('role')
            
            toSerialize = {
                "username": request_data.get('username'),
                "email": request_data.get('email'),
                "password": request_data.get('password'),
                "role": role,
            }
            
            serializer = UserRegisterSerializer(data=toSerialize)

            if serializer.is_valid():
                email = serializer.validated_data.get('email')
                role = serializer.validated_data.get('role')

                if User.objects.filter(email=email).exists():
                    return Response(
                        {"error": "A user with this email already has an active account."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                faculty = request_data.get("faculty")
                major = request_data.get("major")
                yearleveltutor = request_data.get("yearleveltutor")
                yearlevelstudent = request_data.get("yearlevelstudent")
                
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
                Faculty.objects.update_or_create(name=faculty)
                facultyobj = Faculty.objects.get(name=faculty)
                
                
                Major.objects.update_or_create(name=major, faculty=facultyobj)
                
                
                if role == 'student':
                    StudentProfile.objects.create(
                        user=user,
                        faculty=faculty,
                        major=major,
                        academic_year=yearlevelstudent,
                    )
                elif role == 'tutor': 
                    TutorProfile.objects.create(
                        user=user,
                        faculty=faculty,
                        major=major,
                        is_verified = True
                    )
                return Response(
                    {"message": "User registered successfully", "user_id": user.id},
                    status=status.HTTP_201_CREATED
                )

            # Return serializer errors if validation fails
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LoginAPI(APIView):
    authentication_classes = []
    permission_classes = [AllowAny] 
    
    def post(self, request):
        try:
            recv_data = request.data
            logged_user = None
            username_or_email = recv_data.get('username_or_email', '')
            password = recv_data.get('password', '')

            if not username_or_email or not password:
                return Response({"error": "Username/email and password are required"}, status=status.HTTP_400_BAD_REQUEST)

            # Attempt to find the user by username or email
            if '@' in username_or_email:  # If it's an email
                logged_user = User.objects.filter(email=username_or_email).first()
            else:  # If it's a username    
                logged_user = User.objects.filter(username=username_or_email).first()

            if not logged_user:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            # Validate the serializer
            serializer = UserLoginSerializer(data=request.data, context={'request': request})
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            # Extract the authenticated user from validated data
            user = serializer.validated_data['user']

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "role": logged_user.role,
                "username": logged_user.username
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import OutstandingToken, BlacklistedToken
from rest_framework import status

class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            # Get the refresh token from the request data
            refresh_token = request.data.get('refresh_token')

            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Blacklist the provided refresh token
            token = OutstandingToken.objects.filter(token=refresh_token).first()

            if not token:
                return Response(
                    {"error": "Invalid or expired refresh token."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Create a blacklisted token entry
            BlacklistedToken.objects.create(token=token)

            return Response(
                {"message": "Successfully logged out."},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

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
        try:
            queries: dict = request.query_params
            recvdata: dict = request.data
            
            user = request.user
            if user.role != "student":
                return Response({"Error":"A wrong user role."})
            
        
            tutor_id = queries.get("tutor", '')
            tutorID = recvdata.get("tutor", '')
            session_type = recvdata.get("session_type", '')
            requested_time = recvdata.get("requested_time", '')
            tutor = User.objects.get(id=tutorID)
            
            if tutor and tutor.role == "tutor":
                pass
            else:
                return Response({'error':'The user parsed is not a tutor'})
            # print("Sessions: ", dict(SessionRequest.STATUS_CHOICES))
            
            SessionRequest.objects.update_or_create(
                student = user,
                tutor = tutor,
                session_type = session_type,
                requested_time = requested_time,
                defaults={"status": "pending"}
            )
            return Response({"message": "Session request sent"}, status=status.HTTP_201_CREATED)
            
            serializer = SessionRequestSerializer(data=recvdata)
            if serializer.is_valid():
                serializer.save(student=request.user)
                return Response({"message": "Session request sent", "request_id": serializer.data['id']}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({"error":f"an error occurred {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
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
        try:
            all = request.query_params.get('all', '').strip().lower() == 'true'
            tutorname = request.query_params.get('tutorname', '')
            faculty = request.query_params.get('faculty', '')
            major = request.query_params.get('major', '')
            course = request.query_params.get('course', '')
           
            if all:
               tutors = TutorProfile.objects.all()
            # if not tutorname and not faculty and not major and not course:
            #     tutors = TutorProfile.objects.all()
            else:
            # else:
                query = Q()
                if tutorname:
                    query &= Q(user__first_name__icontains=tutorname) | Q(user__last_name__icontains=tutorname)
                    print("tutorname: ", tutorname)
                if faculty:
                    query &= Q(faculty__icontains=faculty)
                    print("faculty: ", faculty)
                if major:
                    query &= Q(major__icontains=major)
                    print("major: ", major)
                if course:
                    query &= Q(course__icontains=course)
                    print("course: ", course)
                tutors = TutorProfile.objects.filter(query)
        
            if tutors.exists():
                res_data = [
                    {
                        "user": tutor.user.id,
                        "faculty":tutor.faculty,
                        "major": tutor.major,
                        "course":tutor.course,
                    }
                    for tutor in tutors
                ]
            else:
                res_data = []
                
            sessions = SessionType.objects.all()
            if not sessions.exists():
                for key_, value_ in dict(SessionType.SESSION_CHOICES).items():
                    SessionType.objects.update_or_create(
                        name=value_
                    )
            
            sessions_ = SessionType.objects.all()
            sessions = [session.name for session in sessions_ if sessions_]
            return Response({"data":res_data, "sessions":sessions}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"Error":e}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        