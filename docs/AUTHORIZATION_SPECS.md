AUTHORIZATION
=============

Permission are checked redundantly to assure as much as possible that users cannot access/modify something they shouldn't.
They are set at model creation and never modified, the principle of least privilege is used in assessing whether a user
should have certain permissions or not. If permissions are not explicitly defined, than the user is taken to not have 
any permissions.

    First level: the permissions assigned at vault creation are checked by the PermissionRequiredMixin in the vault/views
    Second level: by default, the views filter the queryset to only display vault corresponding to the user
    Third level: permissions are checked a third time in the vault/templates 
    (Optional Fourth level: Some views also implement a test_func to further check user authorization)

