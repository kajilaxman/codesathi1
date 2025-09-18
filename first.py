import streamlit as st
import requests
import json
import time
import base64
import re
import hashlib
import sqlite3
from datetime import datetime, timedelta
from PIL import Image
import io
import os

# Page config
st.set_page_config(page_title="CodeSathi 💬", layout="wide")

# Database setup
def init_database():
    """Initialize SQLite database for user authentication"""
    conn = sqlite3.connect('codesathi_users.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            quiz_score_correct INTEGER DEFAULT 0,
            quiz_score_total INTEGER DEFAULT 0
        )
    ''')
    
    # Create sessions table for better session management
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            session_token TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Hash password function
def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

# User registration function
def register_user(username, email, password):
    """Register a new user"""
    try:
        conn = sqlite3.connect('codesathi_users.db')
        cursor = conn.cursor()
        
        # Check if username or email already exists
        cursor.execute('SELECT username, email FROM users WHERE username = ? OR email = ?', (username, email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            if existing_user[0] == username:
                return False, "Username already exists!"
            else:
                return False, "Email already registered!"
        
        # Hash password and insert user
        password_hash = hash_password(password)
        cursor.execute('''
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
        ''', (username, email, password_hash))
        
        conn.commit()
        conn.close()
        return True, "Registration successful! Please login."
        
    except Exception as e:
        return False, f"Registration failed: {str(e)}"

# User login function
def login_user(username, password):
    """Authenticate user login"""
    try:
        conn = sqlite3.connect('codesathi_users.db')
        cursor = conn.cursor()
        
        password_hash = hash_password(password)
        cursor.execute('''
            SELECT id, username, email, quiz_score_correct, quiz_score_total 
            FROM users 
            WHERE username = ? AND password_hash = ?
        ''', (username, password_hash))
        
        user = cursor.fetchone()
        
        if user:
            user_id = user[0]
            # Update last login
            cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user_id,))
            
            # Create session token
            session_token = hashlib.sha256(f"{user_id}_{datetime.now()}".encode()).hexdigest()
            expires_at = datetime.now() + timedelta(hours=24)  # 24 hour session
            
            cursor.execute('''
                INSERT INTO user_sessions (user_id, session_token, expires_at)
                VALUES (?, ?, ?)
            ''', (user_id, session_token, expires_at))
            
            conn.commit()
            conn.close()
            
            return True, {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'quiz_score_correct': user[3],
                'quiz_score_total': user[4],
                'session_token': session_token
            }
        else:
            conn.close()
            return False, "Invalid username or password!"
            
    except Exception as e:
        return False, f"Login failed: {str(e)}"

# Update user quiz score
def update_user_quiz_score(user_id, correct, total):
    """Update user's quiz score in database"""
    try:
        conn = sqlite3.connect('codesathi_users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users 
            SET quiz_score_correct = ?, quiz_score_total = ?
            WHERE id = ?
        ''', (correct, total, user_id))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Failed to update quiz score: {e}")
        return False

# Logout function
def logout_user(session_token):
    """Logout user by invalidating session"""
    try:
        conn = sqlite3.connect('codesathi_users.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM user_sessions WHERE session_token = ?', (session_token,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        return False

# Validate session
def validate_session(session_token):
    """Validate if session is still active"""
    try:
        conn = sqlite3.connect('codesathi_users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT us.user_id, u.username, u.email, u.quiz_score_correct, u.quiz_score_total
            FROM user_sessions us
            JOIN users u ON us.user_id = u.id
            WHERE us.session_token = ? AND us.expires_at > CURRENT_TIMESTAMP
        ''', (session_token,))
        
        session_data = cursor.fetchone()
        conn.close()
        
        if session_data:
            return True, {
                'id': session_data[0],
                'username': session_data[1],
                'email': session_data[2],
                'quiz_score_correct': session_data[3],
                'quiz_score_total': session_data[4]
            }
        else:
            return False, None
            
    except Exception as e:
        return False, None

# Input validation functions
def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

def validate_username(username):
    """Validate username format"""
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    if len(username) > 20:
        return False, "Username must be less than 20 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, "Username is valid"

# Initialize database
init_database()

# Initialize authentication state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user_data" not in st.session_state:
    st.session_state.user_data = None
if "auth_mode" not in st.session_state:
    st.session_state.auth_mode = "login"  # "login" or "register"

# Check for existing session on page load
if not st.session_state.authenticated and "session_token" in st.session_state:
    valid, user_data = validate_session(st.session_state.session_token)
    if valid:
        st.session_state.authenticated = True
        st.session_state.user_data = user_data

# Authentication UI
if not st.session_state.authenticated:
    st.markdown("<h1 style='text-align: center;'>🧑‍💻 CodeSathi: Your AI Coding Companion</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; font-size: 18px;'>Please login or register to continue</p>", unsafe_allow_html=True)
    
    # Create two columns for login/register toggle
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        # Toggle between login and register
        tab1, tab2 = st.tabs(["🔑 Login", "📝 Register"])
        
        with tab1:
            st.markdown("### Welcome Back!")
            
            with st.form("login_form"):
                login_username = st.text_input("Username", key="login_username")
                login_password = st.text_input("Password", type="password", key="login_password")
                login_submit = st.form_submit_button("🚀 Login", use_container_width=True)
                
                if login_submit:
                    if login_username and login_password:
                        success, result = login_user(login_username, login_password)
                        if success:
                            st.session_state.authenticated = True
                            st.session_state.user_data = result
                            st.session_state.session_token = result['session_token']
                            # Load user's quiz scores from database
                            st.session_state.quiz_score = {
                                "correct": result.get('quiz_score_correct', 0),
                                "total": result.get('quiz_score_total', 0)
                            }
                            st.success("Login successful! 🎉")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error(result)
                    else:
                        st.error("Please fill in all fields!")
        
        with tab2:
            st.markdown("### Join CodeSathi!")
            
            with st.form("register_form"):
                reg_username = st.text_input("Username", key="reg_username", help="3-20 characters, letters, numbers, and underscores only")
                reg_email = st.text_input("Email", key="reg_email", help="Valid email address")
                reg_password = st.text_input("Password", type="password", key="reg_password", help="At least 6 characters with letters and numbers")
                reg_confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm_password")
                register_submit = st.form_submit_button("🎯 Register", use_container_width=True)
                
                if register_submit:
                    # Validation
                    if not all([reg_username, reg_email, reg_password, reg_confirm_password]):
                        st.error("Please fill in all fields!")
                    elif reg_password != reg_confirm_password:
                        st.error("Passwords do not match!")
                    else:
                        # Validate inputs
                        username_valid, username_msg = validate_username(reg_username)
                        email_valid = validate_email(reg_email)
                        password_valid, password_msg = validate_password(reg_password)
                        
                        if not username_valid:
                            st.error(username_msg)
                        elif not email_valid:
                            st.error("Please enter a valid email address!")
                        elif not password_valid:
                            st.error(password_msg)
                        else:
                            # Attempt registration
                            success, message = register_user(reg_username, reg_email, reg_password)
                            if success:
                                st.success(message)
                                st.info("Please switch to the Login tab to sign in!")
                            else:
                                st.error(message)

else:
    # Main application (authenticated users only)
    
    # Track whether the assistant is currently generating a response
    if "generating_response" not in st.session_state:
        st.session_state.generating_response = False

    # Initialize dark mode state if not already
    if "dark_mode" not in st.session_state:
        st.session_state.dark_mode = False

    # Initialize code history
    if "code_history" not in st.session_state:
        st.session_state.code_history = []

    # Initialize quiz state (load from user data if not exists)
    if "quiz_data" not in st.session_state:
        st.session_state.quiz_data = None
    if "quiz_answer" not in st.session_state:
        st.session_state.quiz_answer = ""
    if "quiz_submitted" not in st.session_state:
        st.session_state.quiz_submitted = False
    if "quiz_score" not in st.session_state:
        # Load from user data
        st.session_state.quiz_score = {
            "correct": st.session_state.user_data.get('quiz_score_correct', 0),
            "total": st.session_state.user_data.get('quiz_score_total', 0)
        }
    if "quiz_result" not in st.session_state:
        st.session_state.quiz_result = ""
    if "correct_answer" not in st.session_state:
        st.session_state.correct_answer = ""

    # Initialize image analysis state
    if "image_analysis_result" not in st.session_state:
        st.session_state.image_analysis_result = ""
    if "analyzing_image" not in st.session_state:
        st.session_state.analyzing_image = False
    if "current_analysis_image" not in st.session_state:
        st.session_state.current_analysis_image = None

    # Function to convert image to base64
    def image_to_base64(image):
        """Convert PIL Image to base64 string"""
        if isinstance(image, str):
            # If it's already a file path or base64 string, return as is
            return image
        
        # Convert PIL Image to base64
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue()).decode()
        return img_str

    # Function to send image to vision model
    def describe_image_with_vision(image_base64, user_prompt="Describe this image in detail"):
        """Send image to llama3.2-vision model for analysis"""
        try:
            response = requests.post(
                "http://localhost:11434/api/chat",
                json={
                    "model": "llava:7b",
                    "messages": [
                        {
                            "role": "user",
                            "content": user_prompt,
                            "images": [image_base64]
                        }
                    ],
                    "stream": False,
                },
                timeout=60,
            )

            if response.status_code == 200:
                return response.json().get("message", {}).get("content", "Could not analyze the image.")
            else:
                return f"Error analyzing image: HTTP {response.status_code}"

        except Exception as e:
            return f"Error connecting to vision model: {e}"

    # Function to generate quiz using AI and parse it
    def generate_quiz(topic, difficulty, quiz_type):
        """Generate a quiz question using the AI model and parse the response."""
        quiz_prompts = {
            "multiple_choice": f"Generate a {difficulty} level multiple choice question about {topic} programming. Format: Question, then 4 options (A, B, C, D), then the correct answer on a new line starting with 'Correct Answer:' and a brief explanation.",
            "code_output": f"Generate a {difficulty} level 'what will this code output?' question about {topic}. Provide a short code snippet and ask what it outputs. Then provide the correct output on a new line starting with 'Correct Answer:' and an explanation.",
            "debugging": f"Generate a {difficulty} level debugging question about {topic}. Show code with a bug and ask what's wrong. On a new line, starting with 'Correct Answer:', provide the bug description and how to fix it.",
            "concept": f"Generate a {difficulty} level conceptual question about {topic} programming. Ask about best practices, concepts, or methodology. On a new line, starting with 'Correct Answer:', provide a clear answer with explanation."
        }

        prompt = quiz_prompts.get(quiz_type, quiz_prompts["multiple_choice"])

        try:
            response = requests.post(
                "http://localhost:11434/api/chat",
                json={
                    "model": "opencoder:latest",
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                },
                timeout=30,
            )

            if response.status_code == 200:
                full_response = response.json().get("message", {}).get("content", "")
                # Split the response to separate the question and the correct answer
                parts = re.split(r'Correct Answer:', full_response, flags=re.IGNORECASE)
                question_text = parts[0].strip()
                # Store the correct answer and explanation for later checking
                correct_answer_text = parts[1].strip() if len(parts) > 1 else "Answer not found."

                st.session_state.correct_answer = correct_answer_text
                return question_text
            else:
                return "Error generating quiz question. Please try again."

        except Exception as e:
            return f"Error connecting to model: {e}"

    # Function to check quiz answer locally (CORRECTED)
    def check_quiz_answer(user_answer):
        """Check if the user's answer is correct by comparing it to the stored answer."""
        correct_answer_full = st.session_state.correct_answer

        # Extract the core answer from the first line of the correct answer string
        core_answer = correct_answer_full.split('\n')[0].strip()

        # Perform a strict, case-insensitive comparison
        if user_answer.lower().strip() == core_answer.lower().strip():
            return "CORRECT\n\n" + correct_answer_full

        # For multiple-choice, check for just the letter as a fallback
        mc_match = re.search(r'^[a-d]', core_answer, re.IGNORECASE)
        if mc_match and user_answer.lower().strip() == mc_match.group(0).lower():
            return "CORRECT\n\n" + correct_answer_full

        # If neither matches, it's incorrect
        return "INCORRECT\n\n" + "The correct answer was:\n\n" + correct_answer_full

    # Function to extract code blocks from response
    def extract_code_blocks(text):
        """Extract code blocks from markdown text"""
        # Pattern to match code blocks with or without language specification
        code_pattern = r'```(?:\w+)?\n(.*?)\n```'
        code_blocks = re.findall(code_pattern, text, re.DOTALL)

        # Also check for inline code or code-like content
        if not code_blocks:
            # Look for common programming patterns
            if any(keyword in text.lower() for keyword in ['def ', 'function', 'class ', 'import ', 'from ', '#include', 'public class', 'const ', 'let ', 'var ']):
                code_blocks = [text]

        return code_blocks

    # Function to add code to history
    def add_to_code_history(user_query, assistant_response):
        """Add code to history if the response contains code"""
        code_blocks = extract_code_blocks(assistant_response)

        if code_blocks:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # Take first 50 characters of query as title
            title = user_query[:50] + "..." if len(user_query) > 50 else user_query

            history_entry = {
                "timestamp": timestamp,
                "title": title,
                "query": user_query,
                "response": assistant_response,
                "code_blocks": code_blocks
            }

            st.session_state.code_history.insert(0, history_entry)  # Add to beginning

            # Keep only last 20 entries to avoid memory issues
            if len(st.session_state.code_history) > 20:
                st.session_state.code_history = st.session_state.code_history[:20]

    # User profile moved to bottom of sidebar
    def show_user_profile():
        """Display user profile at bottom of sidebar"""
        st.sidebar.markdown("---")
        
        # Get user's initials for avatar
        username = st.session_state.user_data['username']
        initials = ''.join([word[0].upper() for word in username.split()[:2]]) if ' ' in username else username[:2].upper()
        
        # User profile section with avatar
        with st.sidebar.container():
            col1, col2 = st.columns([1, 3])
            
            with col1:
                # Create a simple avatar with initials
                st.markdown(f"""
                <div style="
                    width: 40px; 
                    height: 40px; 
                    border-radius: 50%; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    display: flex; 
                    align-items: center; 
                    justify-content: center;
                    color: white;
                    font-weight: bold;
                    font-size: 14px;
                    margin-top: 5px;
                ">
                    {initials}
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                st.markdown(f"**{username}**")
                st.caption(f"📧 {st.session_state.user_data['email'][:20]}{'...' if len(st.session_state.user_data['email']) > 20 else ''}")
        
        # Logout button with icon
        if st.sidebar.button("🚪 Logout", use_container_width=True, type="secondary"):
            if "session_token" in st.session_state:
                logout_user(st.session_state.session_token)
                del st.session_state.session_token
            st.session_state.authenticated = False
            st.session_state.user_data = None
            # Clear all session states
            for key in list(st.session_state.keys()):
                if key not in ['authenticated', 'user_data', 'auth_mode']:
                    del st.session_state[key]
            st.rerun()

    # Sidebar for code history
    st.sidebar.markdown("## 📚 Code History")

    if st.session_state.code_history:
        st.sidebar.markdown("*Click to view code in main chat*")

        for i, entry in enumerate(st.session_state.code_history):
            # Create an expander for each history entry with better styling
            with st.sidebar.expander(f"🔹 {entry['title'][:30]}{'...' if len(entry['title']) > 30 else ''}", expanded=False):
                st.markdown(f"**📅 Time:** {entry['timestamp']}")
                st.markdown(f"**❓ Query:** {entry['query'][:80]}{'...' if len(entry['query']) > 80 else ''}")
                st.markdown(f"**📊 Code blocks:** {len(entry['code_blocks'])}")

                # Button to load this history entry
                button_key = f"load_history_{i}_{hash(entry['timestamp'])}"
                if st.button(
                    "🔄 Load This Code",
                    key=button_key,
                    disabled=st.session_state.generating_response,
                    use_container_width=True
                ):
                    # Clear current messages and load the historical conversation
                    st.session_state.messages = []
                    st.session_state.messages.append({
                        "role": "user",
                        "content": entry['query'],
                        "is_history": True
                    })
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": entry['response'],
                        "is_history": True
                    })
                    st.rerun()

        st.sidebar.markdown("---")
        # Clear history button
        col1, col2 = st.sidebar.columns([1, 1])
        with col1:
            if st.button("🗑️ Clear All", disabled=st.session_state.generating_response, use_container_width=True):
                st.session_state.code_history = []
                st.rerun()
        with col2:
            if st.button("🔄 New Chat", disabled=st.session_state.generating_response, use_container_width=True):
                st.session_state.messages = []
                st.rerun()
    else:
        st.sidebar.info("💡 No code history yet!\n\nGenerate some code to see it appear here.")

    # Quiz Feature Section
    st.sidebar.markdown("---")
    st.sidebar.markdown("## 🧠 Coding Quiz")

    # Quiz controls
    quiz_topic = st.sidebar.selectbox(
        "📚 Topic:",
        ["Python", "JavaScript", "Java", "C++", "React", "HTML/CSS", "SQL", "Data Structures", "Algorithms"],
        disabled=st.session_state.generating_response
    )

    quiz_difficulty = st.sidebar.selectbox(
        "⚡ Difficulty:",
        ["Beginner", "Intermediate", "Advanced"],
        disabled=st.session_state.generating_response
    )

    quiz_type = st.sidebar.selectbox(
        "🎯 Quiz Type:",
        ["multiple_choice", "code_output", "debugging", "concept"],
        format_func=lambda x: {
            "multiple_choice": "🔘 Multiple Choice",
            "code_output": "📤 Code Output",
            "debugging": "🐛 Debug Code",
            "concept": "💭 Concepts"
        }[x],
        disabled=st.session_state.generating_response
    )

    # Generate new quiz button
    if st.sidebar.button("🎲 Generate New Quiz", disabled=st.session_state.generating_response, use_container_width=True):
        with st.spinner("🤖 Generating quiz..."):
            # Reset quiz state before generating a new one
            st.session_state.quiz_data = None
            st.session_state.quiz_submitted = False
            st.session_state.quiz_answer = ""
            st.session_state.correct_answer = ""
            st.session_state.quiz_result = ""
            st.session_state.quiz_data = generate_quiz(quiz_topic, quiz_difficulty, quiz_type)
        st.rerun()

    # Display current quiz
    if st.session_state.quiz_data:
        st.sidebar.markdown("### 📝 Current Quiz")

        # Show quiz in an expandable container
        with st.sidebar.expander("📋 Quiz Question", expanded=True):
            st.markdown(f"**Topic:** {quiz_topic}")
            st.markdown(f"**Level:** {quiz_difficulty}")
            st.markdown("---")
            st.markdown(st.session_state.quiz_data)

        # Answer input
        if not st.session_state.quiz_submitted:
            st.session_state.quiz_answer = st.sidebar.text_area(
                "✍️ Your Answer:",
                value=st.session_state.quiz_answer,
                height=100,
                placeholder="Type your answer here...",
                disabled=st.session_state.generating_response
            )

            # Submit answer
            if st.sidebar.button("✅ Submit Answer", disabled=st.session_state.generating_response or not st.session_state.quiz_answer.strip(), use_container_width=True):
                result = check_quiz_answer(st.session_state.quiz_answer)

                # Update score
                if result.upper().startswith("CORRECT"):
                    st.session_state.quiz_score["correct"] += 1
                st.session_state.quiz_score["total"] += 1

                # Update database with new scores
                update_user_quiz_score(
                    st.session_state.user_data['id'],
                    st.session_state.quiz_score["correct"],
                    st.session_state.quiz_score["total"]
                )

                # Store result and mark as submitted
                st.session_state.quiz_result = result
                st.session_state.quiz_submitted = True
                st.rerun()

        else:
            # Show results
            result = st.session_state.quiz_result
            if result.upper().startswith("CORRECT"):
                st.sidebar.success("🎉 Correct!")
            else:
                st.sidebar.error("❌ Incorrect")

            # Show feedback in expandable section
            with st.sidebar.expander("📖 Feedback", expanded=True):
                st.markdown(result)

            # Show your answer
            st.sidebar.markdown("**Your Answer:**")
            st.sidebar.info(st.session_state.quiz_answer)

    # Show quiz statistics
    if st.session_state.quiz_score["total"] > 0:
        accuracy = (st.session_state.quiz_score["correct"] / st.session_state.quiz_score["total"]) * 100
        st.sidebar.markdown("### 📊 Quiz Stats")
        st.sidebar.metric(
            "Accuracy",
            f"{accuracy:.1f}%",
            f"{st.session_state.quiz_score['correct']}/{st.session_state.quiz_score['total']}"
        )

        if st.sidebar.button("🔄 Reset Stats", use_container_width=True):
            st.session_state.quiz_score = {"correct": 0, "total": 0}
            # Update database
            update_user_quiz_score(st.session_state.user_data['id'], 0, 0)
            st.rerun()

    else:
        st.sidebar.info("🎯 Generate your first quiz to start learning!")

    # Image Analysis Feature Section
    st.sidebar.markdown("---")
    st.sidebar.markdown("## 🖼️ Image Analysis")

    # Image upload for analysis
    uploaded_image = st.sidebar.file_uploader(
        "📸 Upload Image to Analyze:",
        type=['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'],
        key="sidebar_image_uploader",
        disabled=st.session_state.generating_response or st.session_state.analyzing_image
    )

    # Display uploaded image preview
    if uploaded_image:
        try:
            image = Image.open(uploaded_image)
            st.sidebar.image(image, caption=uploaded_image.name, width=200)
            st.session_state.current_analysis_image = image_to_base64(image)
        except Exception as e:
            st.sidebar.error(f"Error loading image: {e}")
            st.session_state.current_analysis_image = None

    # Analysis prompt input
    analysis_prompt = st.sidebar.text_area(
        "❓ What do you want to know about this image?",
        value="Describe this image in detail",
        height=100,
        placeholder="e.g., 'What objects do you see?', 'Explain this code screenshot', 'What's the main subject?'",
        disabled=st.session_state.generating_response or st.session_state.analyzing_image
    )

    # Analyze button
    if st.sidebar.button(
        "🔍 Analyze Image", 
        disabled=st.session_state.generating_response or st.session_state.analyzing_image or not uploaded_image or not analysis_prompt.strip(),
        use_container_width=True
    ):
        st.session_state.analyzing_image = True
        st.session_state.image_analysis_result = ""
        
        with st.spinner("🤖 Analyzing image..."):
            try:
                result = describe_image_with_vision(st.session_state.current_analysis_image, analysis_prompt)
                st.session_state.image_analysis_result = result
            except Exception as e:
                st.session_state.image_analysis_result = f"❌ Error analyzing image: {e}"
        
        st.session_state.analyzing_image = False
        st.rerun()

    # Display analysis results
    if st.session_state.image_analysis_result:
        st.sidebar.markdown("### 📋 Analysis Result")
        
        with st.sidebar.expander("🔍 Image Analysis", expanded=True):
            st.markdown(st.session_state.image_analysis_result)
        
        # Clear result button
        if st.sidebar.button("🗑️ Clear Analysis", use_container_width=True):
            st.session_state.image_analysis_result = ""
            st.rerun()

    elif not uploaded_image:
        st.sidebar.info("📸 Upload an image above to start analyzing!")

    else:
        st.sidebar.info("✍️ Enter a question and click 'Analyze Image'!")

    # Dark mode toggle (moved before user profile)
    st.sidebar.markdown("---")
    dark_mode = st.sidebar.checkbox(
        "🌙 Dark Mode",
        value=st.session_state.dark_mode,
        disabled=st.session_state.generating_response,
    )
    st.session_state.dark_mode = dark_mode

    # Show user profile at bottom
    show_user_profile()

    # CSS for themes
    light_css = """
    <style>
    body {background-color: #fff; color: #000;}
    .main {max-width: 700px; margin: auto; padding: 20px;}
    .chat-message {padding: 10px 15px; border-radius: 12px; margin-bottom: 10px; max-width: 100%; word-wrap: break-word;}
    .user {background-color: #DCF8C6; color: #000;}
    .assistant {background-color: #F1F0F0; color: #000;}
    .review {background-color: #E0E0FF; color: #000; border-left: 4px solid #6A5ACD;}
    .history-user {background-color: #FFF4E6; color: #000; border-left: 4px solid #FF8C00; border-radius: 12px;}
    .chat-container {display: flex; flex-direction: column;}
    .image-container {margin: 10px 0; text-align: center;}
    .uploaded-image {max-width: 300px; max-height: 300px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);}
    .image-upload-area {
        border: 2px dashed #ccc;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
        background-color: #f9f9f9;
        margin: 10px 0;
    }
    .image-upload-area:hover {
        border-color: #999;
        background-color: #f5f5f5;
    }
    .attachment-button {
        background: none;
        border: none;
        font-size: 20px;
        cursor: pointer;
        padding: 5px;
        border-radius: 50%;
        width: 35px;
        height: 35px;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .attachment-button:hover {
        background-color: #f0f0f0;
    }
    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }
    .spinning-emoji {
      display: inline-block;
      animation: spin 1s linear infinite;
    }
    /* Sidebar styling */
    .stExpander > div:first-child {
        background-color: #f8f9fa;
        border-radius: 8px;
        border: 1px solid #dee2e6;
    }
    .stExpander > div:first-child:hover {
        background-color: #e9ecef;
    }
    </style>
    """

    dark_css = """
    <style>
    body {background-color: #121212; color: #E0E0E0;}
    .main {max-width: 700px; margin: auto; padding: 20px;}
    .chat-message {padding: 10px 15px; border-radius: 12px; margin-bottom: 10px; max-width: 100%; word-wrap: break-word; color: #E0E0E0;}
    .user {background-color: #375A21; color: #E0E0E0;}
    .assistant {background-color: #333333; color: #E0E0E0;}
    .review {background-color: #2A2A72; color: #E0E0E0; border-left: 4px solid #9A79FF;}
    .history-user {background-color: #4A3728; color: #E0E0E0; border-left: 4px solid #FF8C00; border-radius: 12px;}
    .chat-container {display: flex; flex-direction: column;}
    .image-container {margin: 10px 0; text-align: center;}
    .uploaded-image {max-width: 300px; max-height: 300px; border-radius: 8px; box-shadow: 0 2px 8px rgba(255,255,255,0.1);}
    .image-upload-area {
        border: 2px dashed #555;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
        background-color: #2a2a2a;
        margin: 10px 0;
        color: #E0E0E0;
    }
    .image-upload-area:hover {
        border-color: #777;
        background-color: #333;
    }
    .attachment-button {
        background: none;
        border: none;
        font-size: 20px;
        cursor: pointer;
        padding: 5px;
        border-radius: 50%;
        width: 35px;
        height: 35px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #E0E0E0;
    }
    .attachment-button:hover {
        background-color: #444;
    }
    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }
    .spinning-emoji {
      display: inline-block;
      animation: spin 1s linear infinite;
    }
    /* Sidebar styling for dark mode */
    .stExpander > div:first-child {
        background-color: #2b2b2b;
        border-radius: 8px;
        border: 1px solid #404040;
    }
    .stExpander > div:first-child:hover {
        background-color: #3b3b3b;
    }
    /* User avatar styling */
    .user-avatar {
        width: 40px; 
        height: 40px; 
        border-radius: 50%; 
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        display: flex; 
        align-items: center; 
        justify-content: center;
        color: white;
        font-weight: bold;
        font-size: 14px;
        margin-top: 5px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    }
    </style>
    """

    # Apply theme
    if st.session_state.dark_mode:
        st.markdown(dark_css, unsafe_allow_html=True)
    else:
        st.markdown(light_css, unsafe_allow_html=True)

    # Title
    st.markdown(f"<h2 style='text-align: center;'>🧑‍💻 CodeSathi: Your AI Coding Companion</h2>", unsafe_allow_html=True)
    
    # Welcome message for authenticated user
    st.markdown(f"<p style='text-align: center; color: #666;'>Welcome back, <strong>{st.session_state.user_data['username']}</strong>! 🚀</p>", unsafe_allow_html=True)

    # Initialize messages list
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Render messages
    for msg in st.session_state.messages:
        role_class = "user" if msg["role"] == "user" else msg.get("style", "assistant")

        # Special styling for history entries
        if msg.get("is_history", False):
            if msg["role"] == "user":
                role_class = "history-user"
                content = f"📚 <strong>From History:</strong> {msg['content']}"
            else:
                content = msg['content']
        else:
            content = msg["content"]

        with st.chat_message(msg["role"]):
            # Display images if they exist in the message
            if msg.get("images"):
                for img_data in msg["images"]:
                    st.markdown(
                        f"<div class='image-container'><img src='data:image/png;base64,{img_data}' class='uploaded-image' /></div>",
                        unsafe_allow_html=True
                    )
            
            st.markdown(
                f"<div class='chat-container'><div class='chat-message {role_class}'>{content}</div></div>",
                unsafe_allow_html=True
            )

    # Chat input (simplified - removed image upload functionality)
    user_input = st.chat_input("Ask CodeSathi something...", disabled=st.session_state.generating_response)

    # Download link generator - always .txt
    def generate_download_link(code: str, filename: str):
        b64 = base64.b64encode(code.encode()).decode()
        return f'<a href="data:file/txt;base64,{b64}" download="{filename}" style="font-size:16px;">⬇️ Download Code ({filename})</a>'

    # Handle input
    if user_input:
        st.session_state.generating_response = True

        # Simple message without images
        st.session_state.messages.append({"role": "user", "content": user_input})
        
        with st.chat_message("user"):
            st.markdown(
                f"<div class='chat-container'><div class='chat-message user'>{user_input}</div></div>",
                unsafe_allow_html=True
            )

        with st.chat_message("assistant"):
            assistant_placeholder = st.empty()

        assistant_reply = ""

        try:
            # Send to main coding model (no image processing here)
            response = requests.post(
                "http://localhost:11434/api/chat",
                json={
                    "model": "opencoder:latest",
                    "messages": [{"role": "user", "content": user_input}],
                    "stream": True,
                },
                stream=True,
                timeout=60,
            )

            buffer = ""
            last_update = time.time()
            for line in response.iter_lines():
                if line:
                    try:
                        json_data = json.loads(line.decode("utf-8"))
                        token = json_data.get("message", {}).get("content", "")
                        assistant_reply += token
                        buffer += token
                        if time.time() - last_update > 0.2:
                            assistant_placeholder.markdown(
                                f"<div class='chat-container'><div class='chat-message assistant'>{assistant_reply}</div></div>",
                                unsafe_allow_html=True,
                            )
                            buffer = ""
                            last_update = time.time()
                    except json.JSONDecodeError:
                        continue

            # Final update
            assistant_placeholder.markdown(
                f"<div class='chat-container'><div class='chat-message assistant'>{assistant_reply}</div></div>",
                unsafe_allow_html=True,
            )
        except Exception as e:
            assistant_reply = f"⚠️ Error connecting to model: {e}"
            assistant_placeholder.markdown(
                f"<div class='chat-container'><div class='chat-message assistant'>{assistant_reply}</div></div>",
                unsafe_allow_html=True,
            )

        # Save assistant reply message
        st.session_state.messages.append({"role": "assistant", "content": assistant_reply})

        # Add to code history if it contains code
        add_to_code_history(user_input, assistant_reply)

        # ======= DOWNLOAD FEATURE ============
        filename = "code.txt"  # fixed filename with .txt extension
        st.markdown(generate_download_link(assistant_reply, filename), unsafe_allow_html=True)

        # ======= REVIEW PHASE ===============
        review_prompt = f"Please review the following code or explanation and tell whether it's correct, and suggest improvements:\n\n{assistant_reply}"

        with st.chat_message("assistant"):
            review_area = st.empty()

        review_reply = ""
        try:
            review_response = requests.post(
                "http://localhost:11434/api/chat",
                json={
                    "model": "opencoder:latest",
                    "messages": [{"role": "user", "content": review_prompt}],
                    "stream": True,
                },
                stream=True,
                timeout=60,
            )

            buffer = ""
            last_update = time.time()
            for line in review_response.iter_lines():
                if line:
                    try:
                        json_data = json.loads(line.decode("utf-8"))
                        token = json_data.get("message", {}).get("content", "")
                        review_reply += token
                        buffer += token
                        if time.time() - last_update > 0.2:
                            review_area.markdown(
                                f"<div class='chat-container'><div class='chat-message review'><span class='spinning-emoji'>🌀</span> <b>Reviewing code:</b><br>{review_reply}</div></div>",
                                unsafe_allow_html=True,
                            )
                            buffer = ""
                            last_update = time.time()
                    except json.JSONDecodeError:
                        continue

            # Final reviewed text
            review_area.markdown(
                f"<div class='chat-container'><div class='chat-message review'>🌀 <b>Reviewed code:</b><br>{review_reply}</div></div>",
                unsafe_allow_html=True,
            )
        except Exception as e:
            review_reply = f"⚠️ Error during review: {e}"
            review_area.markdown(
                f"<div class='chat-container'><div class='chat-message review'>{review_reply}</div></div>",
                unsafe_allow_html=True,
            )

        st.session_state.messages.append(
            {"role": "assistant", "content": f"🌀 <b>Reviewed code:</b><br>{review_reply}", "style": "review"}
        )

        st.session_state.generating_response = False
        st.rerun()