import re

with open('nrweb/main.py', 'r') as f:
    content = f.read()

# Find the join function parameters and add csrf_token
old_params = '''async def join(
    request: Request,
    userclass: Optional[str] = Form(None),
    accept_general_rules: Optional[bool] = Form(False),
    accept_member_rules: Optional[bool] = Form(False),
    session: SessionData = Depends(get_session),
):'''

new_params = '''async def join(
    request: Request,
    userclass: Optional[str] = Form(None),
    accept_general_rules: Optional[bool] = Form(False),
    accept_member_rules: Optional[bool] = Form(False),
    csrf_token: Optional[str] = Form(None),
    session: SessionData = Depends(get_session),
):'''

content = content.replace(old_params, new_params)

# Find "# Handle form submission" section and add CSRF validation
old_post_check = '''# Handle form submission
    if request.method == "POST" and userclass:
        if not accept_general_rules:'''

new_post_check = '''# Handle form submission
    if request.method == "POST" and userclass:
        # CSRF validation
        if not csrf_token or not validate_csrf_token(session, csrf_token):
            flash(session, "Invalid or missing CSRF token. Please try again.", "danger")
            return redirect_with_session("/join", session)
        
        if not accept_general_rules:'''

content = content.replace(old_post_check, new_post_check)

# Find join form context and add CSRF token
old_return = '''return render(request, "join.html", session, {
        "userclass_choices": userclass_choices,
        "user": user,
    })'''

new_return = '''# Generate CSRF token for the form
    csrf = generate_csrf_token(session)
    
    return render(request, "join.html", session, {
        "userclass_choices": userclass_choices,
        "user": user,
        "csrf_token": csrf,
    })'''

content = content.replace(old_return, new_return)

with open('nrweb/main.py', 'w') as f:
    f.write(content)

print("Patched main.py with CSRF protection")
