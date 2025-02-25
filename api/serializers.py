from rest_framework import serializers
from .models import (
    User, StudentProfile, TutorProfile, Faculty, Major, Course, TutorCourse,
    SessionType, TutorAvailability, TutorPricing, SessionRequest, ScheduledSession,
    Payment, Feedback, Recording, PurchasedRecording, Message, Notification
)

from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model

User = get_user_model()

class FacultySerializer(serializers.ModelSerializer):
    class Meta:
        model = Faculty
        fields = '__all__'

class MajorSerializer(serializers.ModelSerializer):
    faculty = FacultySerializer(read_only=True)

    class Meta:
        model = Major
        fields = '__all__'

class CourseSerializer(serializers.ModelSerializer):
    major = MajorSerializer(read_only=True)

    class Meta:
        model = Course
        fields = '__all__'

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'role']

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            role=validated_data['role']
        )
        return user

class UserLoginSerializer(serializers.Serializer):
    username_or_email = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        username_or_email = data.get('username_or_email')
        password = data.get('password')

        if not username_or_email or not password:
            raise serializers.ValidationError("Both username/email and password are required.")

        # Authenticate the user using either username or email
        user = None
        if '@' in username_or_email:  # Check if it's an email
            try:
                user = User.objects.get(email=username_or_email)
                username = user.username
            except User.DoesNotExist:
                raise serializers.ValidationError("User with this email does not exist.")
        else:  # Assume it's a username
            username = username_or_email

        user = authenticate(username=username, password=password)

        if not user:
            raise serializers.ValidationError("Invalid credentials.")

        if not user.is_active:
            raise serializers.ValidationError("This user account is disabled.")

        data['user'] = user
        return data

class TutorProfileSerializer(serializers.ModelSerializer):
    faculty = FacultySerializer(read_only=True)
    courses = CourseSerializer(many=True, read_only=True, source='tutcourse_set')

    class Meta:
        model = TutorProfile
        fields = '__all__'

class SessionTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = SessionType
        fields = '__all__'

class TutorAvailabilitySerializer(serializers.ModelSerializer):
    tutor = serializers.HiddenField(default=serializers.CurrentUserDefault())
    session_type = SessionTypeSerializer(read_only=True)

    class Meta:
        model = TutorAvailability
        fields = '__all__'

    def create(self, validated_data):
        # Extract session type ID from request data
        session_type_id = self.initial_data.get('session_type')
        validated_data['session_type'] = SessionType.objects.get(id=session_type_id)
        return super().create(validated_data)

class SessionRequestSerializer(serializers.ModelSerializer):
    student = serializers.HiddenField(default=serializers.CurrentUserDefault())
    tutor = serializers.StringRelatedField(read_only=True)
    session_type = SessionTypeSerializer(read_only=True)

    class Meta:
        model = SessionRequest
        fields = '__all__'

    def create(self, validated_data):
        # Extract session type ID from request data
        session_type_id = self.initial_data.get('session_type')
        validated_data['session_type'] = SessionType.objects.get(id=session_type_id)
        return super().create(validated_data)

class FeedbackSerializer(serializers.ModelSerializer):
    from_user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    to_user = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = Feedback
        fields = '__all__'

class RecordingSerializer(serializers.ModelSerializer):
    tutor = serializers.HiddenField(default=serializers.CurrentUserDefault())
    course = CourseSerializer(read_only=True)

    class Meta:
        model = Recording
        fields = '__all__'

    def create(self, validated_data):
        # Extract course ID from request data
        course_id = self.initial_data.get('course')
        validated_data['course'] = Course.objects.get(id=course_id)
        return super().create(validated_data)

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'

class MessageSerializer(serializers.ModelSerializer):
    sender = serializers.HiddenField(default=serializers.CurrentUserDefault())
    receiver = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = Message
        fields = '__all__'

class NotificationSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = Notification
        fields = '__all__'