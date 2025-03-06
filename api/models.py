from django.contrib.auth.models import AbstractUser
from django.db import models

from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    ROLE_CHOICES = [
        ('student', 'Student'),
        ('tutor', 'Tutor'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    first_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100, blank=True, null=True)
    full_name = models.CharField(max_length=100, blank=True, null=True)
    

    # Override the groups and user_permissions fields to avoid clashes
    groups = models.ManyToManyField(
        'auth.Group',
        blank=True,
        related_name='api_user_set',  # Unique related_name for groups
        verbose_name='groups',
        help_text='The groups this user belongs to.',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        blank=True,
        related_name='api_user_set',  # Unique related_name for user_permissions
        verbose_name='user permissions',
        help_text='Specific permissions for this user.',
    )
    
class StudentProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    # faculty = models.ForeignKey('Faculty', on_delete=models.CASCADE)
    # major = models.ForeignKey('Major', on_delete=models.CASCADE)
    faculty = models.TextField(blank=True, null=True)
    course = models.TextField(blank=True, null=True)
    major = models.TextField(blank=True, null=True)
    academic_year = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
class TutorProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    # faculty = models.ForeignKey('Faculty', on_delete=models.CASCADE)
    faculty = models.TextField(blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    # major = models.ForeignKey('Major', on_delete=models.CASCADE)
    major = models.TextField(blank=True, null=True)
    year_level = models.TextField(blank=True, null=True)
    course = models.TextField(blank=True, null=True)
    experience = models.TextField(blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    search_visibility = models.CharField(max_length=10, choices=[('standard', 'Standard'), ('premium', 'Premium')])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    
class Faculty(models.Model):
    name = models.CharField(max_length=100)
    
class Major(models.Model):
    name = models.CharField(max_length=100)
    faculty = models.ForeignKey(Faculty, on_delete=models.CASCADE)
    
class Course(models.Model):
    name = models.CharField(max_length=100)
    major = models.ForeignKey(Major, on_delete=models.CASCADE)
    
class TutorCourse(models.Model):
    tutor = models.ForeignKey(User, on_delete=models.CASCADE)
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    proof_document = models.CharField(max_length=255)  # File path or URL
    grade_achieved = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    
class SessionType(models.Model):
    SESSION_CHOICES = [
        ('one-on-one', 'One-on-One'), 
        ('group', 'Group'), 
        ('recorded', 'Recorded')
    ]
    name = models.CharField(max_length=20, choices=[('one-on-one', 'One-on-One'), ('group', 'Group'), ('recorded', 'Recorded')])
    
    def __str__(self):
        return self.name
    
class TutorAvailability(models.Model):
    tutor = models.ForeignKey(User, on_delete=models.CASCADE)
    session_type = models.ForeignKey(SessionType, on_delete=models.CASCADE)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

class TutorPricing(models.Model):
    tutor = models.ForeignKey(User, on_delete=models.CASCADE)
    session_type = models.ForeignKey(SessionType, on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)


class SessionRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('declined', 'Declined'),
    ]
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='student_requests')
    tutor = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tutor_requests')
    # session_type = models.ForeignKey(SessionType, on_delete=models.CASCADE)
    session_type = models.TextField(null=True, blank=True)
    message = models.TextField(null=True, blank=True)
    requested_time = models.DateTimeField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    decline_reason = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
class Chats(models.Model):
    tutor = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_tutor')
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_student')
    session = models.ForeignKey(SessionRequest, on_delete=models.CASCADE)
    
    
class ScheduledSession(models.Model):
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('refunded', 'Refunded'),
    ]
    session_request = models.ForeignKey(SessionRequest, on_delete=models.CASCADE)
    scheduled_time = models.DateTimeField()
    payment_status = models.CharField(max_length=10, choices=PAYMENT_STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    
class Payment(models.Model):
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('held', 'Held'),
        ('released', 'Released'),
        ('refunded', 'Refunded'),
    ]
    scheduled_session = models.ForeignKey(ScheduledSession, on_delete=models.CASCADE, null=True, blank=True)
    purchased_recording = models.ForeignKey('PurchasedRecording', on_delete=models.CASCADE, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    platform_fee = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_id = models.CharField(max_length=100)
    status = models.CharField(max_length=10, choices=PAYMENT_STATUS_CHOICES, default='pending')
    payment_date = models.DateTimeField(auto_now_add=True)
    
class Feedback(models.Model):
    scheduled_session = models.ForeignKey(ScheduledSession, on_delete=models.CASCADE)
    from_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='feedback_given')
    to_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='feedback_received')
    rating = models.IntegerField()
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
class Recording(models.Model):
    tutor = models.ForeignKey(User, on_delete=models.CASCADE)
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = models.TextField()
    file_url = models.CharField(max_length=255)
    upload_date = models.DateTimeField(auto_now_add=True)
    
class PurchasedRecording(models.Model):
    student = models.ForeignKey(User, on_delete=models.CASCADE)
    recording = models.ForeignKey(Recording, on_delete=models.CASCADE)
    purchase_date = models.DateTimeField(auto_now_add=True)
    
class Message(models.Model):
    chat = models.ForeignKey(Chats, on_delete=models.CASCADE)
    sender = models.CharField(max_length=250, null=True, blank=True)
    receiver = models.CharField(max_length=250, null=True, blank=True)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    read_status_tutor = models.BooleanField(default=False)
    read_status_student = models.BooleanField(default=False)
    
class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('request', 'Request'),
        ('reminder', 'Reminder'),
        ('update', 'Update'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.TextField()
    type = models.CharField(max_length=10, choices=NOTIFICATION_TYPES)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
