from django.urls import path
from .views import (
    RegisterAPI, LoginAPI,
    BrowseTutorsAPI, RequestSessionAPI, LeaveFeedbackAPI,
    SetAvailabilityAPI, AcceptDeclineSessionAPI, RecordingAPI,
    MakePaymentAPI, SendMessageAPI, GetMessagesAPI,
    GetNotificationsAPI, SearchTutorsAPI, LogoutAPIView, 
    GetAllTutorsAPI, GetAllStudentsAPI, GetAllRequestsAPI, 
    RequestSessionListAPI, GetTransactionsAPI, WithdrawalRequestAPI,
    StudentDashboardAPI, TutorDashboardAPI
) 

urlpatterns = [
    # Authentication
    path('register/', RegisterAPI.as_view(), name='register'),
    path('login/', LoginAPI.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),

    # Student Path
    path('student-dashboard/', StudentDashboardAPI.as_view(), name='student-dashboard'),
    path('browse-tutors/', BrowseTutorsAPI.as_view(), name='browse-tutors'),
    path('request-session/', RequestSessionAPI.as_view(), name='request-session'),
    path('leave-feedback/', LeaveFeedbackAPI.as_view(), name='leave-feedback'),
 
    path('recording/', RecordingAPI.as_view(), name='recording'),
    
    # Tutor Path
    path('tutor-dashboard/', TutorDashboardAPI.as_view(), name='tutor-dashboard'),
    path('set-availability/', SetAvailabilityAPI.as_view(), name='set-availability'),
    path('request-session-listings/', RequestSessionListAPI.as_view(), name='request-session-list'),
    path('accept-decline-session/<int:request_id>/', AcceptDeclineSessionAPI.as_view(), name='accept-decline-session'),

    # Payment
    path('make-payment/', MakePaymentAPI.as_view(), name='make-payment'),
    # 
    path('get-transactions/', GetTransactionsAPI.as_view(), name='get-transactions'),
    path('withdrawal/', WithdrawalRequestAPI.as_view(), name='withdrawal'),

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