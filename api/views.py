import random
import string
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from api.models import (
    User, TutorProfile, SessionRequest, Feedback, TutorAvailability,
    Recording, Payment, Message, Notification, StudentProfile, TutorProfile,
    Faculty, Major, SessionType, Chats, Message, Withdrawal, PurchasedRecording
)
from api.serializers import (
    UserRegisterSerializer, UserLoginSerializer, TutorProfileSerializer,
    SessionRequestSerializer, FeedbackSerializer, TutorAvailabilitySerializer,
    RecordingSerializer, PaymentSerializer, MessageSerializer, NotificationSerializer
)
from django.db.models import Q
from api.permissions import AllowAny
from datetime import datetime, timedelta
from django.utils import timezone
 
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
            role = request_data.get('role').strip().lower()
            
            toSerialize = {
                "username": request_data.get('username').strip().lower(),
                "full_name":request_data.get("fullname").strip().lower(),
                "email": request_data.get('email').strip().lower(),
                "password": request_data.get('password').strip().lower(),
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

                faculty = request_data.get("faculty").strip().lower()
                major = request_data.get("major").strip().lower()
                courses = request_data.get("courses").strip().lower()
                yearleveltutor = request_data.get("yearleveltutor").strip().lower()
                yearlevelstudent = request_data.get("yearlevelstudent").strip().lower()
                
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
                        course=courses
                    ) 
                elif role == 'tutor': 
                    TutorProfile.objects.create(
                        user=user,
                        faculty=faculty,
                        major=major,
                        is_verified = True,
                        year_level = yearleveltutor,
                        course=courses
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
            username_or_email: str = recv_data.get('username_or_email').strip().lower()
            username_or_email = username_or_email.strip().lower()
            password: str = recv_data.get('password', '').strip().lower()
            password = password.strip().lower()
            
            data = {
                "username_or_email": username_or_email,
                "password": password
            }

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
            serializer = UserLoginSerializer(data=data, context={'request': request})
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
                "username": logged_user.username,
                "email": logged_user.email,
                "faculty": TutorProfile.objects.get(user=logged_user).faculty if logged_user.role == "tutor" else StudentProfile.objects.get(user=logged_user).faculty,
                "major": TutorProfile.objects.get(user=logged_user).major if logged_user.role == "tutor" else StudentProfile.objects.get(user=logged_user).major,
                "rate": None,
                "rating": None
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
    
# Student Path Views
class DashboardAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            
            if user.role == "student":
                sessions = SessionRequest.objects.filter(student=user)
                pending_requests = SessionRequest.objects.filter(student=user, status='pending').count()
                accepted_bookings = SessionRequest.objects.filter(student=user, status='accepted').count()
                current_time = timezone.now() 
                
                data = {
                    "upcoming":accepted_bookings,
                    "pending":pending_requests,
                    "recorded":0,
                    "upcoming_sessions":[
                        {
                        'tutor_name': session.tutor.full_name,  
                        'session_type': session.session_type,
                        "course":TutorProfile.objects.get(user=session.tutor).course,
                        'requested_time': session.requested_time.strftime('%Y-%m-%d %H:%M'),
                        'status': session.status
                        }
                        for session in sessions 
                        if session.requested_time > current_time and session.status == 'accepted'
                    ]
                }
            elif user.role == "tutor":
                sessions = SessionRequest.objects.filter(tutor=user)
                pending_requests = SessionRequest.objects.filter(tutor=user, status='pending').count()
                accepted_bookings = SessionRequest.objects.filter(tutor=user, status='accepted').count()
                current_time = timezone.now() 
                
                data = {
                    "accepted_bookings":accepted_bookings,
                    "pending_requests":pending_requests,
                    "earnings": format(user.earnings, '.2f'),
                    "upcoming_sessions":[
                        {
                        'student_name': session.student.full_name,  
                        'session_type': session.session_type,
                        "course":TutorProfile.objects.get(user=session.tutor).course,
                        'requested_time': session.requested_time.strftime('%Y-%m-%d %H:%M'),
                        'status':session.status
                        }
                        for session in sessions 
                        if session.requested_time > current_time and session.status == 'accepted'
                    ]
                }
            else:
                return Response({"error": "Invalid user"})
            
            return Response({"data": data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "An error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class RequestSessionListAPI(APIView): 
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            queries: dict = request.query_params
            path = queries.get("query", None)
            user = request.user
            request_id = None
            
            print("path: ", path)
            
            if path is None:
                return Response({"Error": "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)
            
            if path.lower() == 'search':
                request_id = queries.get('id', None)
            
            if request_id:
                try:
                    if user.role == "student":
                        session = SessionRequest.objects.get(id=request_id, student=user)
                    else:
                        session = SessionRequest.objects.get(id=request_id, tutor=user)
                except Exception as e:
                    return Response({'error': 'Invalid session id provided'}, status=status.HTTP_400_BAD_REQUEST)
                
                data = {
                    "tutor": session.tutor.full_name,
                    "session_type": session.session_type,
                    "message": session.message,
                    "time": session.requested_time,
                    "status": session.status,
                    "decline_reason" : session.decline_reason
                }
                return Response({'data': data}, status=status.HTTP_200_OK)
                
            if user.role == "student" and path.lower() == "all":
                sessions_pending = SessionRequest.objects.filter(student=user, status="pending")
                sessions_accepted = SessionRequest.objects.filter(student=user, status="accepted")
                sessions_completed = SessionRequest.objects.filter(student=user, status="completed")
                sessions_declined = SessionRequest.objects.filter(student=user, status="declined")
                
                pending = [
                    {
                        "name":req.student.full_name,
                        "session_type": req.session_type,
                        "course": StudentProfile.objects.get(user=req.student).course,
                        "message":req.message,
                        "request_date":req.requested_time,
                        "request_id":req.id,
                        "tutor":req.tutor.username,
                        "tutor_id":req.tutor.id,
                        "status":req.status,
                    }
                    for req in sessions_pending
                ]
                
                accepted = [
                    {
                        "name":req.student.full_name,
                        "session_type": req.session_type,
                        "course": StudentProfile.objects.get(user=req.student).course,
                        "message":req.message,
                        "request_date":req.requested_time,
                        "request_id":req.id,
                        "tutor":req.tutor.username,
                        "tutor_id":req.tutor.id,
                        "status":req.status
                    }
                    for req in sessions_accepted
                ]
                
                completed = [
                    {
                        "name":req.student.full_name,
                        "session_type": req.session_type,
                        "course": StudentProfile.objects.get(user=req.student).course,
                        "message":req.message,
                        "request_date":req.requested_time,
                        "request_id":req.id,
                        "tutor":req.tutor.username,
                        "tutor_id":req.tutor.id,
                        "status":req.status
                    }
                    for req in sessions_completed
                ]
                
                declined = [
                    {
                        "name":req.student.full_name,
                        "session_type": req.session_type,
                        "course": StudentProfile.objects.get(user=req.student).course,
                        "message":req.message,
                        "request_date":req.requested_time,
                        "request_id":req.id,
                        "tutor":req.tutor.username,
                        "tutor_id":req.tutor.id,
                        "status":req.status,
                        "decline_reason": req.decline_reason
                    }
                    for req in sessions_declined
                ]
                
                return Response({"pending":pending, "accepted": accepted, "completed": completed, "declined": declined}, status=status.HTTP_200_OK)
            
            
            if path.lower() == "pending":
                if user.role == "tutor":
                    reqs = SessionRequest.objects.filter(tutor=user, status="pending")
                    
                else:
                    return Response({"error": "The user is forbidden"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                resp_list = [
                    {
                        "name":req.student.full_name,
                        "session_type": req.session_type,
                        "course": StudentProfile.objects.get(user=req.student).course,
                        "message":req.message,
                        "request_date":req.requested_time,
                        "request_id":req.id,
                        "tutor":req.tutor.username,
                        "status":req.status
                    }
                    for req in reqs
                ]
            elif path.lower() == "accepted":
                if user.role == "tutor":
                    reqs = SessionRequest.objects.filter(tutor=user, status="accepted")
                else:
                    return Response({"error": "The user is forbidden"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                resp_list = [
                    {
                        "name":req.student.full_name,
                        "session_type": req.session_type,
                        "course": StudentProfile.objects.get(user=req.student).course,
                        "message":req.message,
                        "request_date":req.requested_time,
                        "request_id":req.id,
                        "student":req.student.id
                    }
                    for req in reqs
                ]
            else:
                resp_list = []
                
            return Response({"data": resp_list}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"An error occurred. {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request):
        try:
            data: dict = request.data
            
            session_id = data.get('request_session_id', '')
            sessions = SessionRequest.objects.filter(id=session_id)
            if sessions:
                for session in sessions:
                    session.status = "Accepted"
                    session.save()
                    Chats.objects.update_or_create(user=request.user, session=session)
                    
                    
                return Response({"message": "Request accepted"})
            else:
                return Response({"error": "The request id not found"}, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            return Response({"error": f"INTERNAL SERVER ERROR: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
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
            session_type_ = recvdata.get("session_type", '')
            requested_time = recvdata.get("requested_time", '')
            message = recvdata.get("message", '')
            tutor = User.objects.get(id=tutorID)
            
            session_type = SessionType.objects.get(name = session_type_)
            if not session_type:
                return Response({"error": "invalid session type"})
            
            if tutor and tutor.role == "tutor":
                pass
            else:
                return Response({'error':'The tutor does not exist'})
            # print("Sessions: ", dict(SessionRequest.STATUS_CHOICES))
            
            SessionRequest.objects.create(
                student = user,
                tutor = tutor,
                session_type = session_type,
                requested_time = requested_time,
                status="pending",
                message = message
            )
            # return Response({"message": "Session request sent"}, status=status.HTTP_201_CREATED)
            return Response({"message": "Session request sent"}, status=status.HTTP_200_OK)
            
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
 
    def post(self, request, request_id):
        queries: dict = request.query_params
        action = queries.get('action', None)
        
        if action is None:
            return Response({'error': "No action defined"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            session_request = SessionRequest.objects.get(id=request_id, status='pending')
            if session_request:
                if action.lower() == 'accept':
                    session_request.status = "accepted"
                    session_request.save()
                    
                    Chats.objects.update_or_create(
                        tutor = session_request.tutor,
                        student= session_request.student,
                        session = session_request
                    )
                    
                    user = User.objects.get(id=request.user.id)
                    bal = float(user.earnings) + float("15")
                    user.earnings = bal
                    user.save()
                    
                    return Response({"message":"request successfully accepted"})
                
                elif action.lower() == 'decline':
                    decline_reason = request.data.get('decline_reason')
                    session_request.status = "declined"
                    session_request.decline_reason = decline_reason
                    session_request.save()
                    return Response({"message":"request successfully declined"})
                
                else:
                    return Response({"message":"unknown action"})
                
        except:
            return Response({'error': "Session request not found"}, status=status.HTTP_400_BAD_REQUEST)
        
        
    # def patch(self, request, request_id):
    #     try: 
    #         session_request = SessionRequest.objects.get(id=request_id, tutor=request.user)
    #     except SessionRequest.DoesNotExist:
    #         return Response({"error": "Session request not found"}, status=status.HTTP_404_NOT_FOUND)

    #     status_action = request.data.get('status')
    #     if status_action not in ['accepted', 'declined']:
    #         return Response({"error": "Invalid status"}, status=status.HTTP_400_BAD_REQUEST)

    #     session_request.status = status_action
    #     if status_action == 'declined':
    #         session_request.decline_reason = request.data.get('decline_reason', '')
    #     session_request.save()

    #     return Response({"message": f"Session request {status_action}"}, status=status.HTTP_200_OK)

class FetchVideoAPIView(APIView):
    def get(self, request, recording_id, *args, **kwargs):
        try:
            course_material = get_object_or_404(Recording, id=int(recording_id))
            file_path = course_material.file.path

            return FileResponse(open(file_path, 'rb'), content_type='video/mp4')
        except Exception as e:
            return Response({"error": "an error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RecordingAPI(APIView): 
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def get(self, request):
        try:
            user = request.user
            if user.role == "student":
                recordings = Recording.objects.all()
                purchased = PurchasedRecording.objects.filter(student = user)
                data = {
                    "recorded":[
                        {
                            # "course": TutorProfile.objects.get(user=recording.tutor).course,
                            "course": recording.course,
                            "tutor": recording.tutor.full_name,
                            "title":recording.title,
                            "url": recording.file.path,
                            "cost": f"{float(recording.cost):.2f}",
                            "description": recording.description,
                            "recording_id": recording.pk
                        }
                        for recording in recordings
                    ],
                    "purchased":[
                        {
                            # "course": TutorProfile.objects.get(user=recording_.recording.tutor).course,
                            "course": recording_.recording.course,
                            "tutor": recording_.recording.tutor.full_name,
                            "title":recording_.recording.title,
                            "url": recording_.recording.file.path,
                            "purchased_date": recording_.purchase_date,
                            "description": recording_.recording.description
                        }
                        for recording_ in purchased
                    ]
                }
            else:
                recordings = Recording.objects.filter(tutor = user)
                data = {
                    "uploads": [
                        {
                            "title": recording.title,
                            "course": recording.course,
                            "cost": f"{float(recording.cost):.2f}",
                            "recording_id": recording.pk
                        }
                        for recording in recordings
                    ]
                }
            return Response({"data":data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"An error occurred. {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request, *args, **kwargs):
        try:
            if 'file' not in request.FILES:
                return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)

            # uploaded_file = request.FILES['file']
            # file_path = f"media/{uploaded_file.name}"
            # with open(file_path, 'wb+') as destination:
            #     for chunk in uploaded_file.chunks():
            #         destination.write(chunk)
                    
            user = request.user
            queries: dict = request.query_params
            data: dict = request.data
            
            query = queries.get("query", None)
            
            if query == "upload" and user.role == "tutor":
                title = data.get("title")
                course = data.get("course")
                price = data.get("price")
                description = data.get("description")
                file = data.get("file_url")
                
                uploaded_file = request.FILES.get('file')
                
                print("Title: ", title)
                print("Course: ", course)
                print("price: ", price)
                print("description: ", description)
                print("File: ", uploaded_file)

                if not all([title, course, price, description, uploaded_file]):
                    return Response({'error': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)

                
                Recording.objects.create(
                    tutor = user,
                    course = course,
                    title = title,
                    description = description,
                    file_url = file,
                    file = uploaded_file,
                    cost = price
                )
                return Response({"message": "successfully uploaded"}, status=status.HTTP_200_OK)
            
            else:
                return Response({"error": "Invalid request"}, status=status.HTTP_406_NOT_ACCEPTABLE)
        except Exception as e:
            return Response({"error": f"An error occurred. {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)        
        
def generate_transaction_id():
    chars = string.ascii_uppercase + string.digits
    while True:
        random_part = ''.join(random.choices(chars, k=7))
        tid = f"WTD{random_part}"
        if not Withdrawal.objects.filter(transaction_id=tid).exists():
            return tid

class WithdrawalRequestAPI(APIView):
    permission_classes = [IsAuthenticated]
  
    def post(self, request):
        try:
            data = request.data  # Ensure data is parsed as JSON
            user = request.user
            if user.role != "tutor":
                return Response({"error": "Invalid user"}, status=status.HTTP_400_BAD_REQUEST)
            
            amount = float(data.get("amount"))
            userobj = User.objects.get(id=user.id)
            if float(userobj.earnings) - amount < 0:
                return Response({"message": "Insufficient funds."}, status=status.HTTP_400_BAD_REQUEST)
            
            balance_ = float(userobj.earnings)
            balance = round(balance_ - amount, 2)
            userobj.earnings = balance
            userobj.save()
            
            # Use Withdrawal's static method to generate the transaction ID
            withdrawal = Withdrawal.objects.create(
                tutor=user,
                amount=amount,
                transaction_id=generate_transaction_id()  # ✅ Use the model's method
            )
            
            return Response(
                {"message": "Withdrawal successful", "withdrawal_id": withdrawal.transaction_id},
                status=status.HTTP_201_CREATED
            )
        except ValueError:
            return Response({"error": "Invalid amount"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
def generate_transaction_id_payment():
    chars = string.ascii_uppercase + string.digits
    while True:
        random_part = ''.join(random.choices(chars, k=7))
        tid = f"TXN{random_part}"
        if not Payment.objects.filter(transaction_id=tid).exists():
            return tid
        
class MakePaymentAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            data: dict = request.data
            user = request.user
            
            if user.role != "student":
                return Response({"error":"user not allowed to perform the transaction"}, status=status.HTTP_404_NOT_FOUND)
            
            amount = data.get("amount", None)
            platform_fee = data.get("platform_fee", None)
            
            payment = Payment.objects.create(
                transaction_id = generate_transaction_id_payment(),
                student=user,
                amount=float(amount),
                platform_fee=float(platform_fee),
                expiration_date = timezone.now() + timedelta(days=30)
            )
            
            user = User.objects.get(id=user.id)
            user.subscribed = True
            user.save()
            
            return Response({"message": "Payment successful", "payment_id": payment.transaction_id}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": f"An error occurred. {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetTransactionsAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            user = request.user
            balance = 0
            if user.role != "student":
                transactions = Withdrawal.objects.filter(tutor = user)
                balance = format(user.earnings, '.2f')
                data = [
                    {
                        "amount": format(transaction.amount, '.2f'),
                        "transaction_id": transaction.transaction_id,
                        "payment_date": transaction.payment_date.strftime('%Y-%m-%d %H:%M'),
                        "status": transaction.status
                    }
                    for transaction in transactions
                ]
            else:
                transactions = Payment.objects.filter(student=user)
                data = [
                        {
                            "amount": format(transaction.amount, '.2f'),
                            "transaction_id": transaction.transaction_id,
                            "payment_date": transaction.payment_date.strftime('%Y-%m-%d %H:%M'),
                            "Expiration_date": transaction.expiration_date.strftime('%Y-%m-%d %H:%M'),
                            "status": transaction.status
                        }
                        for transaction in transactions
                ]
            return Response({"data": data, "balance": balance}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "An error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Messaging Views
class SendMessageAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data: dict = request.data
        user = request.user
        
        session_request_id = data.get("session_request_id", None)
        message = data.get("content", None)
        
        try:
            chat = Chats.objects.get(session=session_request_id)
            read_status_tutor = False
            read_status_student = False
            
            if user.role == "student":
                sender_id = chat.student.id
                receiver_id = chat.tutor.id
                read_status_student = True
            else:
                sender_id = chat.tutor.id
                receiver_id = chat.student.id
                read_status_tutor = True
                
            Message.objects.create(
                chat=chat,
                sender = sender_id,
                receiver = receiver_id,
                content=message,
                read_status_student=read_status_student,
                read_status_tutor=read_status_tutor
            )
            return Response({"message":"message succesfully sent."})
        except Exception as e:
            return Response({"error": f"An error occurred."}, status=status.HTTP_404_NOT_FOUND)
        
class GetMessagesAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def format_datetime(self, dt:datetime):
        formatted = dt.strftime("%Y-%m-%d %I:%M %p")
        formatted = formatted.replace("AM", "a.m").replace("PM", "p.m")
        return formatted

    def get(self, request):
        queries: dict = request.query_params
        user = request.user
        
        ret_resp = []
        chats_dict = {}
        
        query = queries.get("query", None)
        if query.lower() == "all":
            ret_resp = []
            if user.role == "student":
                chats = Chats.objects.filter(student=user)
            else:
                chats = Chats.objects.filter(tutor=user)
                
            for chat in chats:
                chats_dict = {}
                message = Message.objects.filter(chat=chat).last()
                if user.role == "student":
                    unread_count = Message.objects.filter(chat=chat, read_status_student=False).count()
                else:
                    unread_count = Message.objects.filter(chat=chat, read_status_tutor=False).count()
                
                chats_dict['chat_session_id'] = chat.session.id
                chats_dict['unread_count'] = unread_count

                if user.role == "student":
                    chats_dict['full_name'] = chat.tutor.full_name
                else:
                    chats_dict['full_name'] = chat.student.full_name
                    
                if message:
                    chats_dict['message'] = message.content
                    chats_dict['time'] = self.format_datetime(message.timestamp)
                    
                else:
                    chats_dict['message'] = "No message"
                    chats_dict['time'] = "N/A"
                    
                ret_resp.append(chats_dict)
        else:
            ret_resp = []
            request_id = query
            session_ = SessionRequest.objects.filter(id=request_id)
            if session_.exists():
                for session in session_:
                    chats = Chats.objects.filter(session=session)
                    if not chats.exists():
                        return Response({"error": "The requested chat does not exist.."}, status=status.HTTP_404_NOT_FOUND)
        
                    for chat in chats:
                        messages = Message.objects.filter(chat=chat)
                        if not messages.exists():
                            return Response({"data": []}, status=status.HTTP_200_OK)
                        
                        for message in messages:
                            if user.role == "student":
                                message.read_status_student = True
                            else:
                                message.read_status_tutor = True
                            message.save()
                            chats_dict = {}
                            chats_dict['sender'] = "me" if message.sender == str(user.id) else "not me"
                            chats_dict['content'] = message.content
                            
                            ret_resp.append(chats_dict)
                
            else:
                return Response({"error": "The requested chat does not exist"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({"data": ret_resp}, status=status.HTTP_200_OK)

# Notification Views
class GetNotificationsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_id = request.user.id
        notifications = Notification.objects.filter(user_id=user_id)
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

# Notification Views
class GetAllTutorsAPI(APIView):
    authentication_classes = []
    permission_classes = [AllowAny] 

    def get(self, request):
         
        usser = User.objects.filter(role="tutor")
        
        data = [
            {
                "UserName": us.username,
                "Full Name": us.full_name,
                "ID": us.id,
                "Email": us.email
            }
            for us in usser
        ]
        return Response({"data": data}, status=status.HTTP_200_OK)

class GetAllStudentsAPI(APIView):
    authentication_classes = []
    permission_classes = [AllowAny] 

    def get(self, request):
        
        usser = User.objects.filter(role="student")
        
        data = [
            {
                "UserName": us.username,
                "Full Name": us.full_name,
                "ID": us.id,
                "Email": us.email
            }
            for us in usser
        ]
        return Response({"data": data}, status=status.HTTP_200_OK)

class GetAllRequestsAPI(APIView):
    # authentication_classes = []
    permission_classes = [IsAuthenticated] 

    def get(self, request):
        
        user = request.user
        if user.role != "tutor":
            return Response({'error': 'An error just occurred'}, status=status.HTTP_204_NO_CONTENT)
        
        query_params: dict = request.query_params
        query: str = query_params.get('query')
        
        if query.lower() == "pending":
            sessions = SessionRequest.objects.filter(tutor=user, status='pending')
        elif query.lower() == "accepted":
            sessions = SessionRequest.objects.filter(tutor=user, status='accepted')
        else:
            return Response({"error": "Invalid query parameter"})
        
        usser = User.objects.filter(role="student")
        
        data = [
            {
                "UserName": us.username,
                "Full Name": us.full_name,
                "ID": us.id,
                "Email": us.email
            }
            for us in usser
        ]
        return Response({"data": data}, status=status.HTTP_200_OK)

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
                        "name": f'{tutor.user.full_name}',
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
                        name=key_
                    )
            
            sessions_ = SessionType.objects.all()
            sessions = [session.name for session in sessions_ if sessions_]
            return Response({"data":res_data, "sessions":sessions}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"Error":e}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        