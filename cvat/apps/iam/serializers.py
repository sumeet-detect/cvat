# Copyright (C) 2022 Intel Corporation
# Copyright (C) 2022 CVAT.ai Corporation
#
# SPDX-License-Identifier: MIT

from dj_rest_auth.registration.serializers import RegisterSerializer, SocialLoginSerializer
from dj_rest_auth.serializers import PasswordResetSerializer, LoginSerializer
from rest_framework.exceptions import ValidationError
from rest_framework import serializers
from allauth.account import app_settings
from allauth.account.utils import filter_users_by_email
from django.contrib.auth.models import User
import logging

from django.conf import settings

from cvat.apps.iam.forms import ResetPasswordFormEx

class RegisterSerializerEx(RegisterSerializer):
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)

    def get_cleaned_data(self):
        data = super().get_cleaned_data()
        data.update({
            'first_name': self.validated_data.get('first_name', ''),
            'last_name': self.validated_data.get('last_name', ''),
        })

        return data

class PasswordResetSerializerEx(PasswordResetSerializer):
    @property
    def password_reset_form_class(self):
        return ResetPasswordFormEx

    def get_email_options(self):
        domain = None
        if hasattr(settings, 'UI_HOST') and settings.UI_HOST:
            domain = settings.UI_HOST
            if hasattr(settings, 'UI_PORT') and settings.UI_PORT:
                domain += ':{}'.format(settings.UI_PORT)
        return {
            'domain_override': domain
        }

class LoginSerializerEx(LoginSerializer):
    def get_auth_user_using_allauth(self, username, email, password):
        if username:
            try:
                user= User.objects.get(username=username)
                user.email = email
                user.save()
            except Exception as e:
                print("Error occured ",e)
        return self._validate_username(username, password)

class SocialLoginSerializerEx(SocialLoginSerializer):
    auth_params = serializers.CharField(required=False, allow_blank=True, default='')
    process = serializers.CharField(required=False, allow_blank=True, default='login')
    scope = serializers.CharField(required=False, allow_blank=True, default='')

    def get_social_login(self, adapter, app, token, response):
        request = self._get_request()
        social_login = adapter.complete_login(request, app, token, response=response)
        social_login.token = token

        social_login.state = {
            'process': self.initial_data.get('process'),
            'scope': self.initial_data.get('scope'),
            'auth_params': self.initial_data.get('auth_params'),
        }

        return social_login
