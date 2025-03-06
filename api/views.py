from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from api.models import (
    User, TutorProfile, SessionRequest, Feedback, TutorAvailability,
    Recording, Payment, Message, Notification, StudentProfile, TutorProfile,
    Faculty, Major, SessionType, Chats, Message
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
        queries: dict = request.query_params
        user = request.user
        
        ret_resp = []
        chats_dict = {}
        
        query = queries.get("query", '')
        if query.lower() == "all":
            ret_resp = []
            chats = Chats.objects.filter(user=user)
            for chat in chats:
                chats_dict = {}
                message = Message.objects.filter(chat=chat, receiver=user).last()
                if message:
                    chats_dict['full_name'] = chat.user.full_name
                    chats_dict['message'] = message.content
                    chats_dict['time'] = message.timestamp
                else:
                    chats_dict['full_name'] = chat.user.full_name
                    chats_dict['message'] = "No message"
                    chats_dict['time'] = "N/A"
                    
                ret_resp.append(chats_dict)
        else:
            ret_resp = []
            request_id = query
            session_ = SessionRequest.objects.filter(id=request_id)
            if session_.exists():
                for session in session_:
                    chats = Chats.objects.filter(user=user, session=session)
                    for chat in chats:
                        messages = Message.objects.filter(chat=chat)
                        for message in messages:
                            chats_dict = {}
                            chats_dict['sender'] = message.sender
                            if message.receiver == user:
                                chats_dict['receiver'] = "me"
                                
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
                        name=value_
                    )
            
            sessions_ = SessionType.objects.all()
            sessions = [session.name for session in sessions_ if sessions_]
            return Response({"data":res_data, "sessions":sessions}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"Error":e}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        