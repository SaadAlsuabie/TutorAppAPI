from django.urls import path
from .views import (
    RegisterAPI, LoginAPI,
    BrowseTutorsAPI, RequestSessionAPI, LeaveFeedbackAPI,
    SetAvailabilityAPI, AcceptDeclineSessionAPI, UploadRecordingAPI,
    MakePaymentAPI, SendMessageAPI, GetMessagesAPI,
    GetNotificationsAPI, SearchTutorsAPI, LogoutAPIView, 
    GetAllTutorsAPI, GetAllStudentsAPI, GetAllRequestsAPI
)

urlpatterns = [
    # Authentication
    path('register/', RegisterAPI.as_view(), name='register'),
    path('login/', LoginAPI.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),

    # Student Path
    path('browse-tutors/', BrowseTutorsAPI.as_view(), name='browse-tutors'),
    path('request-session/', RequestSessionAPI.as_view(), name='request-session'),
    path('leave-feedback/', LeaveFeedbackAPI.as_view(), name='leave-feedback'),
 
    # Tutor Path
    path('set-availability/', SetAvailabilityAPI.as_view(), name='set-availability'),
    path('accept-decline-session/<int:request_id>/', AcceptDeclineSessionAPI.as_view(), name='accept-decline-session'),
    path('upload-recording/', UploadRecordingAPI.as_view(), name='upload-recording'),

    # Payment
    path('make-payment/', MakePaymentAPI.as_view(), name='make-payment'),

    # Messaging
    path('send-message/', SendMessageAPI.as_view(), name='send-message'),
    path('get-messages/', GetMessagesAPI.as_view(), name='get-messages'),

    # Notifications
    path('get-notifications/', GetNotificationsAPI.as_view(), name='get-notifications'),

    # Search
    path('search-tutors/', SearchTutorsAPI.as_view(), name='search-tutors'),
    
    # Search
    path('get-all-tutors/', GetAllTutorsAPI.as_view(), name='get-all-tutors'),
    path('get-all-students/', GetAllStudentsAPI.as_view(), name='get-all-students'),
    path('get-all-requests/', GetAllRequestsAPI.as_view(), name='get-all-requests')
] 