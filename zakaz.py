import sys
import sqlite3
import logging
import bcrypt
from datetime import datetime
from functools import wraps
from aiogram import Bot, Dispatcher, executor, types
from aiogram.contrib.middlewares.logging import LoggingMiddleware
from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram.contrib.fsm_storage.memory import MemoryStorage
from aiogram.types import ReplyKeyboardMarkup, ReplyKeyboardRemove, ParseMode
from dotenv import load_dotenv
import os
import getpass  # Admin yaratishda foydalanish uchun

# ----------------------------
# 1. LOG & BOT SETTINGS
# ----------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()
API_TOKEN = os.getenv("BOT_API_TOKEN")  # <-- Yangi tokeningizni .env faylida belgilashingiz kerak

if not API_TOKEN:
    logger.error("❌ BOT_API_TOKEN o'zgaruvchisi topilmadi. Iltimos, .env faylini tekshiring.")
    sys.exit(1)

bot = Bot(token=API_TOKEN)
storage = MemoryStorage()
dp = Dispatcher(bot, storage=storage)
dp.middleware.setup(LoggingMiddleware())

# ----------------------------
# 2. DATABASE FUNCTIONS
# ----------------------------

DB_FILE = "bot_database.db"

PRODUCT_PRICES = {
    "PREMIUM": 900000,
    "KAPSULA": 550000,
    "MILANO": 1500000,
    "COMFORT": 2800000,
    "SULTAN": 1200000,
    "SOFT MEMORY": 1200000,
    "MONDO": 900000,
    "SOFT SLEEP": 450000,
    "RELAX": 550000,
    "LIGHT": 350000,
    "STRONG": 500000,
    "DETSKIY MATRAS": 250000,
    "TOPPER 5cm": 490000,
    "TOPPER 8cm": 650000,
    "Sovutadigan Yostiq": 160000,
    "16 HOLLOFAYBER Yostig": 120000,
    "NM 2X1.8": 200000,
    "NM 2.1×1.7": 210000,
    "NM 2x1.6": 190000,
    "NM 2x0.5": 150000
}

SIZES = [
    "190x90", "200x90", "200x100", "200x120", "200x150",
    "200x160", "200x180", "200x200", "210x170", "210x180",
    "Nestandart razmer"
]

# Mahsulotlar o'lchami oldindan belgilanganlar to'plami
PRODUCTS_WITH_FIXED_SIZE = {
    "NM 2X1.8",
    "NM 2.1×1.7",
    "NAMATRASNIK 2x1.6",
    "NM 2x0.5",
    "16 HOLLOFAYBER Yostig",
    "Sovutadigan Yostiq",
}

def init_db():
    """Ma'lumotlar bazasini va kerakli jadvallarni yaratadi yoki yangilaydi."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # Foydalanuvchilar jadvali
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'sotuvchi',
            telegram_id INTEGER UNIQUE,
            telegram_username TEXT UNIQUE,
            last_login TEXT
        )
        """)
        # Buyurtmalar jadvali
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            products TEXT NOT NULL,
            total_price REAL NOT NULL,
            payment REAL DEFAULT 0,
            remaining_payment REAL DEFAULT 0,
            customer_name TEXT NOT NULL,
            customer_surname TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            location TEXT NOT NULL,
            detailed_address TEXT,
            delivery_time TEXT NOT NULL,
            order_date TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        )
        """)
        conn.commit()
        logger.info("✅ Ma'lumotlar bazasi muvaffaqiyatli yaratildi yoki yangilandi.")
    except sqlite3.Error as e:
        logger.error(f"❌ Ma'lumotlar bazasini yaratishda xatolik: {e}")
    finally:
        conn.close()

def hash_password(password):
    """Parolni bcrypt yordamida hashing qiladi."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    """Parolni hashing qilingan parol bilan solishtiradi."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except ValueError:
        logger.error("❌ Noto'g'ri tuzilgan hash formatida parol tekshirildi.")
        return False

def insert_user(login, full_name, phone_number, password, role='sotuvchi', telegram_id=None, telegram_username=None):
    """Yangi foydalanuvchini ro'yxatdan o'tkazadi."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (login, full_name, phone_number, password, role, telegram_id, telegram_username, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (login, full_name, phone_number, password, role, telegram_id, telegram_username, datetime.utcnow().isoformat()))
        conn.commit()
        return True
    except sqlite3.IntegrityError as e:
        logger.error(f"❌ Foydalanuvchini qo'shishda xatolik: {e}")
        return False
    finally:
        conn.close()

def get_user_by_login(login):
    """Login bo'yicha foydalanuvchini oladi."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE login = ?", (login,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_telegram_id(telegram_id):
    """Telegram ID bo'yicha foydalanuvchini oladi."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE telegram_id = ?", (telegram_id,))
    user = cursor.fetchone()
    conn.close()
    return user

def authenticate_user_admin(login, password):
    """Admin foydalanuvchini autentifikatsiya qiladi."""
    user = get_user_by_login(login)
    if user and verify_password(password, user[4]):  # user[4] - password maydoni
        if user[5].lower() == 'admin':  # user[5] - role
            return user
    return None

def authenticate_user_regular(username, password):
    """Oddiy foydalanuvchini autentifikatsiya qiladi."""
    user = get_user_by_login(username)
    if user and verify_password(password, user[4]):
        return user
    return None

def update_user_telegram_id(user_id, telegram_id, telegram_username):
    """Foydalanuvchining Telegram ID va username sini yangilaydi."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET telegram_id = ?, telegram_username = ?, last_login = ? WHERE user_id = ?",
                       (telegram_id, telegram_username, datetime.utcnow().isoformat(), user_id))
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"❌ Telegram ID va username ni yangilashda xatolik: {e}")
    finally:
        conn.close()

def save_order(user_id, products, total_price, payment, customer_name, customer_surname, phone_number, location, detailed_address, delivery_time):
    """Buyurtmani ma'lumotlar bazasiga saqlaydi."""
    remaining_payment = total_price - payment
    order_date = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    products_str = "; ".join([f"{p['name']} ({p['size']}) - {p['quantity']} ta - {p['unit_price']:,.0f} so'm" for p in products])
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO orders (
                user_id, products, total_price, payment, remaining_payment,
                customer_name, customer_surname, phone_number,
                location, detailed_address, delivery_time, order_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            products_str,
            total_price,
            payment,
            remaining_payment,
            customer_name,
            customer_surname,
            phone_number,
            location,
            detailed_address,
            delivery_time,
            order_date
        ))
        conn.commit()
        logger.info("✅ Buyurtma muvaffaqiyatli saqlandi!")
        return True
    except sqlite3.Error as e:
        logger.error(f"❌ Buyurtmani saqlashda xatolik: {e}")
        return False
    finally:
        conn.close()

def get_user_orders(user_id):
    """Foydalanuvchining barcha buyurtmalarini oladi."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, products, total_price, payment, remaining_payment,
                   customer_name, customer_surname, phone_number,
                   location, detailed_address, delivery_time, order_date
            FROM orders
            WHERE user_id = ?
            ORDER BY id ASC
        """, (user_id,))
        orders = cursor.fetchall()
        return orders
    except sqlite3.Error as e:
        logger.error(f"❌ Buyurtmalarni olishda xatolik: {e}")
        return []
    finally:
        conn.close()

def get_all_orders():
    """Barcha buyurtmalarni oladi (admin uchun)."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT users.login, users.full_name, users.phone_number, users.telegram_username, users.role,
                   orders.id, orders.products, orders.total_price, orders.payment, orders.remaining_payment,
                   orders.customer_name, orders.customer_surname, orders.phone_number,
                   orders.location, orders.detailed_address, orders.delivery_time, orders.order_date
            FROM orders
            JOIN users ON orders.user_id = users.user_id
            ORDER BY users.login ASC, orders.id ASC
        """)
        orders = cursor.fetchall()
        return orders
    except sqlite3.Error as e:
        logger.error(f"❌ Barcha buyurtmalarni olishda xatolik: {e}")
        return []
    finally:
        conn.close()

def kick_user_by_telegram_id(telegram_id):
    """Foydalanuvchini Telegram ID orqali tizimdan chiqaradi."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET telegram_id = NULL, telegram_username = NULL, last_login = NULL WHERE telegram_id = ?", (telegram_id,))
        conn.commit()
        return True
    except sqlite3.Error as e:
        logger.error(f"❌ Foydalanuvchini chiqarishda xatolik: {e}")
        return False
    finally:
        conn.close()

def get_admins():
    """Barcha admin foydalanuvchilarni oladi."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE role = 'admin'")
        admins = cursor.fetchall()
        return admins
    except sqlite3.Error as e:
        logger.error(f"❌ Adminlarni olishda xatolik: {e}")
        return []
    finally:
        conn.close()

def get_admins_by_telegram_id(telegram_id):
    """Berilgan Telegram ID ga ega bo'lgan adminlarni oladi."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE role = 'admin' AND telegram_id = ?", (telegram_id,))
        admins = cursor.fetchall()
        return admins
    except sqlite3.Error as e:
        logger.error(f"❌ Adminlarni olishda xatolik: {e}")
        return []
    finally:
        conn.close()

def create_admin():
    """Komanda satri orqali admin foydalanuvchi yaratadi (faqat Login va Parol so'raydi)."""
    print("🔧 Admin yaratish jarayoni boshlandi.")
    
    # 📛 Login so'rash
    login = input("📛 Login: ").strip()
    if not login:
        print("❌ Login bo'sh bo'lishi mumkin emas.")
        return
    
    # 🔒 Parol so'rash
    password = getpass.getpass("🔒 Parol: ").strip()
    while len(password) < 4:
        print("❌ Parol kamida 4 ta belgidan iborat bo'lishi kerak.")
        password = getpass.getpass("🔒 Parol: ").strip()
    
    # Parolni hashing qilish
    hashed_password = hash_password(password)
    role = 'admin'
    
    # Default qiymatlarni belgilash
    full_name = 'Admin'
    phone_number = '900000000'  # Siz istagan standart telefon raqamini kiriting
    
    # Foydalanuvchini bazaga qo'shish
    success = insert_user(login, full_name, phone_number, hashed_password, role)
    if success:
        print("✅ Admin foydalanuvchi muvaffaqiyatli yaratildi.")
    else:
        print("❌ Admin foydalanuvchini qo'shishda xatolik yuz berdi. Ehtimol, login allaqachon mavjud.")

# ----------------------------
# 3. STATE GROUPS
# ----------------------------

class LoginTypeState(StatesGroup):
    choosing = State()

class AdminLoginState(StatesGroup):
    login = State()
    password = State()

class UserLoginState(StatesGroup):
    username = State()
    password = State()

class AdminAddUserState(StatesGroup):
    login = State()
    full_name = State()
    phone_number = State()
    role = State()
    password = State()
    confirmation = State()

class HelpProcess(StatesGroup):
    waiting_for_message = State()

class OrderProcess(StatesGroup):
    product = State()
    size = State()
    custom_size = State()  # For 'Nestandart razmer'
    quantity = State()
    confirm_sum = State()
    adjust_price = State()  # Yangi holat: Narxni o'zgartirish
    confirm_adjusted_sum = State()  # Yangi holat: O'zgartirilgan sumni tasdiqlash
    add_more = State()
    customer_name = State()
    customer_surname = State()
    phone_number = State()
    location = State()
    detailed_address = State()
    delivery_time = State()
    custom_delivery_date = State()  # Yangi holat: Boshqa sana kiritish
    confirm_order = State()

# ----------------------------
# 4. DECORATORS
# ----------------------------

def admin_only(handler):
    """Decorator: Faqat admin foydalanuvchilarga ruxsat beradi."""
    @wraps(handler)
    async def wrapper(message: types.Message, *args, **kwargs):
        user = get_user_by_telegram_id(message.from_user.id)
        if not user:
            logger.info(f"Foydalanuvchi topilmadi: Telegram ID {message.from_user.id}")
            await message.reply("❌ Siz admin emas ekansiz.")
            return
        logger.info(f"Foydalanuvchi roli: {user[5]}")
        if user[5].lower() != 'admin':  # user[5] - role field
            await message.reply("❌ Siz admin emas ekansiz.")
            return
        return await handler(message, *args, **kwargs)
    return wrapper

def restricted_commands_only(commands):
    """Decorator: Faqat belgilangan komandalarni qabul qiladi."""
    def decorator(handler):
        @wraps(handler)
        async def wrapper(message: types.Message, *args, **kwargs):
            command = message.text.split()[0]
            if command not in commands:
                await message.reply("❌ Bu komanda ruxsat etilmagan yoki mavjud emas.")
                return
            return await handler(message, *args, **kwargs)
        return wrapper
    return decorator

# ----------------------------
# 5. BOT COMMAND HANDLERS
# ----------------------------

@dp.message_handler(commands=['start'])
async def start_command(message: types.Message, state: FSMContext):
    """Botni boshlash va foydalanuvchini ro'yxatdan o'tkazish yoki kirishni taklif qilish."""
    user = get_user_by_telegram_id(message.from_user.id)
    if user:
        if user[5].lower() == 'admin':
            await message.reply("✅ Siz admin sifatida tizimga kirdingiz.\n📦 Barcha buyurtmalarni ko'rish uchun /all_orders, yangi foydalanuvchi qo'shish uchun /add_user buyrug'ini yuboring.")
        else:
            # Foydalanuvchi allaqachon tizimga kirgan bo'lsa, faqat tugmalarni ko'rsatish
            user_buttons = ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add("📦 Buyurtma Qo'shish", "📄 Buyurtmalarni Ko'rish")
            await message.reply("✅ Siz allaqachon tizimga kirdingiz.\n📦 Buyurtmalarni ko'rish yoki yangi buyurtma qo'shish uchun quyidagi tugmalardan birini tanlang:", reply_markup=user_buttons)
    else:
        # Foydalanuvchi ro'yxatdan o'tmagan, login turini tanlash
        login_type_markup = ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add("👑 Admin Login", "🔑 User Login")
        await message.reply("👋 Assalomu alaykum! Iltimos, tizimga kirish turini tanlang:", reply_markup=login_type_markup)
        await LoginTypeState.choosing.set()

@dp.message_handler(state=LoginTypeState.choosing)
async def choose_login_type(message: types.Message, state: FSMContext):
    """Login turini tanlash (Admin yoki User)."""
    choice = message.text.strip()
    if choice == "👑 Admin Login":
        await message.reply("🔑 Iltimos, admin loginini kiriting:", reply_markup=ReplyKeyboardRemove())
        await AdminLoginState.login.set()
    elif choice == "🔑 User Login":
        await message.reply("👤 Iltimos, username ni kiriting:", reply_markup=ReplyKeyboardRemove())
        await UserLoginState.username.set()
    else:
        await message.reply("❌ Iltimos, faqat berilgan variantlardan birini tanlang.")
        return

@dp.message_handler(state=AdminLoginState.login)
async def admin_login_get_login(message: types.Message, state: FSMContext):
    """Admin loginini qabul qilish."""
    login = message.text.strip()
    user = get_user_by_login(login)
    if not user:
        await message.reply("❌ Bu login mavjud emas. Iltimos, to'g'ri login kiriting.")
        await state.finish()
    else:
        await state.update_data(login=login)
        await message.reply("🔒 Parolingizni kiriting:")
        await AdminLoginState.next()

@dp.message_handler(state=AdminLoginState.password)
async def admin_login_get_password(message: types.Message, state: FSMContext):
    """Admin parolini qabul qilish va autentifikatsiya."""
    password = message.text.strip()
    data = await state.get_data()
    user = authenticate_user_admin(data['login'], password)
    if user:
        # Eski adminlarni olish (agar adminning oldingi telegram_id'si mavjud bo'lsa)
        old_admins = []
        if user[6] and user[6] != message.from_user.id:
            old_admins = get_admins_by_telegram_id(user[6])

        # Telegram ID va username ni yangilash
        update_user_telegram_id(user[0], message.from_user.id, message.from_user.username)

        # Yangi login haqida adminlarga xabar yuborish
        updated_user = get_user_by_telegram_id(message.from_user.id)
        if updated_user:
            await notify_admins_of_login(updated_user)

        # Agar eski adminlar mavjud bo'lsa, ularga xabar yuborish
        for admin in old_admins:
            admin_telegram_id = admin[6]
            if admin_telegram_id:
                try:
                    await bot.send_message(
                        admin_telegram_id,
                        f"🔔 **Diqqat!** Admin @{user[1]} tizimga yangi Telegram ID bilan kirildi: {message.from_user.id}"
                    )
                except Exception as e:
                    logger.error(f"❌ Eski adminga xabar yuborishda xatolik: {e}")

        # Foydalanuvchiga (adminga) login haqida hech qanday ma'lumot yuborilmaydi
        await message.reply(
            "✅ Admin sifatida tizimga muvaffaqiyatli kirdingiz.\n📦 Barcha buyurtmalarni ko'rish uchun /all_orders, yangi foydalanuvchi qo'shish uchun /add_user buyrug'ini yuboring."
        )
        await state.finish()
    else:
        await message.reply("❌ Login yoki parol noto'g'ri. Iltimos, qayta urinib ko'ring.")
        await state.finish()

@dp.message_handler(state=UserLoginState.username)
async def user_login_get_username(message: types.Message, state: FSMContext):
    """User username ni qabul qilish."""
    username = message.text.strip()
    user = get_user_by_login(username)
    if not user:
        await message.reply("❌ Bu username mavjud emas. Iltimos, to'g'ri username kiriting.")
        await state.finish()
    else:
        await state.update_data(username=username)
        await message.reply("🔒 Parolingizni kiriting:")
        await UserLoginState.next()

@dp.message_handler(state=UserLoginState.password)
async def user_login_get_password(message: types.Message, state: FSMContext):
    """Oddiy foydalanuvchi parolini qabul qilish va autentifikatsiya."""
    password = message.text.strip()
    data = await state.get_data()
    username = data.get('username')
    user = authenticate_user_regular(username, password)
    if user:
        # Eski adminlarni olish (agar foydalanuvchi admin bo'lsa va oldingi Telegram ID mavjud bo'lsa)
        old_admins = []
        if user[5].lower() == 'admin' and user[6] and user[6] != message.from_user.id:
            old_admins = get_admins_by_telegram_id(user[6])

        # Telegram ID va username ni yangilash
        update_user_telegram_id(user[0], message.from_user.id, message.from_user.username)

        # Yangi login haqida adminlarga xabar yuborish
        updated_user = get_user_by_telegram_id(message.from_user.id)
        if updated_user:
            await notify_admins_of_login(updated_user)

        # Agar eski adminlar mavjud bo'lsa, ularga xabar yuborish
        for admin in old_admins:
            admin_telegram_id = admin[6]
            if admin_telegram_id:
                try:
                    await bot.send_message(
                        admin_telegram_id,
                        f"🔔 **Diqqat!** Foydalanuvchi @{user[1]} tizimga yangi Telegram ID bilan kirildi: {message.from_user.id}"
                    )
                except Exception as e:
                    logger.error(f"❌ Eski adminga xabar yuborishda xatolik: {e}")

        # Foydalanuvchiga faqat kerakli tugmalarni ko'rsatish
        user_buttons = ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add("📦 Buyurtma Qo'shish", "📄 Buyurtmalarni Ko'rish")
        await message.reply(
            "✅ Tizimga muvaffaqiyatli kirdingiz.\n📦 Buyurtmalarni ko'rish yoki yangi buyurtma qo'shish uchun quyidagi tugmalardan birini tanlang:",
            reply_markup=user_buttons
        )
        await state.finish()
    else:
        await message.reply("❌ Parol noto'g'ri yoki siz ro'yxatdan o'tmagan. Iltimos, qayta urinib ko'ring yoki admin bilan bog'laning.")
        await state.finish()

import csv
import io

@dp.message_handler(commands=['my_orders'])
@restricted_commands_only(['/my_orders'])
async def my_orders_command(message: types.Message):
    """Foydalanuvchining buyurtmalarini CSV fayli sifatida ko'rsatish."""
    user = get_user_by_telegram_id(message.from_user.id)
    if not user:
        await message.reply("❌ Siz tizimga kirmagansiz. Iltimos, /start buyrug'ini yuboring.")
        return
    orders = get_user_orders(user[0])
    if not orders:
        await message.reply("📭 Siz hali birorta ham buyurtma bermagansiz.")
        return

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    # Write header
    writer.writerow([
        "Buyurtma ID", "Mahsulotlar", "Umumiy summa", "To'langan",
        "Qoldiq", "Mijoz Ismi", "Mijoz Familiyasi",
        "Telefon", "Manzil", "Yetkazib berish muddati", "Buyurtma sana"
    ])
    # Write order data
    for order in orders:
        writer.writerow(order)

    output.seek(0)
    file = io.BytesIO(output.read().encode())
    file.name = "buyurtmalar.csv"

    try:
        await bot.send_document(chat_id=message.chat.id, document=file, caption="📄 Sizning buyurtmalaringiz:")
    except Exception as e:
        logger.error(f"❌ CSV faylini yuborishda xatolik: {e}")
        await message.reply("❌ Buyurtmalarni yuborishda xatolik yuz berdi.")

@dp.message_handler(commands=['admin'])
@restricted_commands_only(['/admin'])
async def admin_login_command(message: types.Message, state: FSMContext):
    """Admin login jarayonini boshlash."""
    await message.reply("👑 **Admin login**\nIltimos, admin login ni kiriting:")
    await AdminLoginState.login.set()

# ----------------------------
# 6. ADMIN FUNCTIONS
# ----------------------------

@dp.message_handler(commands=['add_user'])
@admin_only
@restricted_commands_only(['/add_user'])
async def add_user_command(message: types.Message):
    """Yangi foydalanuvchini qo'shish jarayonini boshlash (faqat admin uchun)."""
    await message.reply("🆕 **Yangi foydalanuvchini qo'shish uchun login ni kiriting (Loginga uning Telegram usernamesini kiritishingiz tavsiya etiladi):")
    await AdminAddUserState.login.set()

@dp.message_handler(state=AdminAddUserState.login)
async def admin_add_user_login(message: types.Message, state: FSMContext):
    """Yangi foydalanuvchi uchun login ni qabul qilish."""
    login = message.text.strip()
    if login.startswith('/'):
        await message.reply("❌ Login komanda sifatida qabul qilinmaydi. Iltimos, boshqa login tanlang.")
        return
    if get_user_by_login(login):
        await message.reply("❌ Bu login allaqachon olingan. Iltimos, boshqa login tanlang.")
    else:
        await state.update_data(login=login)
        await message.reply("👤 **FIO** ni kiriting:")
        await AdminAddUserState.next()

@dp.message_handler(state=AdminAddUserState.full_name)
async def admin_add_user_full_name(message: types.Message, state: FSMContext):
    """Yangi foydalanuvchi uchun FIO ni qabul qilish."""
    full_name = message.text.strip()
    if not full_name:
        await message.reply("❌ FIO bo'sh bo'lishi mumkin emas. Iltimos, FIO ni kiriting.")
        return
    await state.update_data(full_name=full_name)
    await message.reply("📱 **Telefon raqamini kiriting (9 raqam):**")
    await AdminAddUserState.next()

@dp.message_handler(state=AdminAddUserState.phone_number)
async def admin_add_user_phone_number(message: types.Message, state: FSMContext):
    """Yangi foydalanuvchi uchun telefon raqamini qabul qilish."""
    phone_number = message.text.strip()
    await state.update_data(phone_number=phone_number)
    await message.reply(
        "👑 **Rolni tanlang:**",
        reply_markup=ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add("admin", "sotuvchi")
    )
    await AdminAddUserState.next()

@dp.message_handler(state=AdminAddUserState.role)
async def admin_add_user_role(message: types.Message, state: FSMContext):
    """Yangi foydalanuvchi uchun rolni tanlash."""
    role = message.text.strip().lower()
    if role not in ["admin", "sotuvchi"]:
        await message.reply(
            "❌ Noto'g'ri rol. Iltimos, 'admin' yoki 'sotuvchi' ni tanlang.",
            reply_markup=ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add("admin", "sotuvchi")
        )
        return
    await state.update_data(role=role)
    await message.reply("🔒 **Parolni kiriting:**")
    await AdminAddUserState.next()

@dp.message_handler(state=AdminAddUserState.password)
async def admin_add_user_password(message: types.Message, state: FSMContext):
    """Yangi foydalanuvchi uchun parolni qabul qilish."""
    password = message.text.strip()
    if len(password) < 4:
        await message.reply("❌ Parol kamida 4 ta belgidan iborat bo‘lishi kerak. Iltimos, qayta kiriting.")
        return
    hashed_password = hash_password(password)
    await state.update_data(password=hashed_password)
    confirm_markup = ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add("✅ Ha", "❌ Yo'q")
    data = await state.get_data()
    # Mapping 'sotuvchi' to 'User' for clarity
    account_type = "Admin" if data['role'].lower() == 'admin' else "Sotuvchi"
    response = (
        f"**Login:** {data['login']}\n"
        f"**FIO:** {data['full_name']}\n"
        f"**Telefon:** {data['phone_number']}\n"
        f"**Rol:** {account_type}\n\n"
        f"📜 **Ma'lumotlar to'g'rimi?**"
    )
    await message.reply(response, reply_markup=confirm_markup, parse_mode=ParseMode.MARKDOWN)
    await AdminAddUserState.confirmation.set()

@dp.message_handler(state=AdminAddUserState.confirmation)
async def admin_add_user_confirmation(message: types.Message, state: FSMContext):
    """Yangi foydalanuvchini tasdiqlash yoki bekor qilish."""
    data = await state.get_data()
    if message.text == "✅ Ha":
        success = insert_user(
            login=data['login'],
            full_name=data['full_name'],
            phone_number=data['phone_number'],
            password=data['password'],
            role=data['role'],
            telegram_id=None,  # Telegram ID tizimga kirganida yangilanadi
            telegram_username=None
        )
        if success:
            await message.reply("✅ Yangi foydalanuvchi muvaffaqiyatli qo'shildi.", reply_markup=ReplyKeyboardRemove())
        else:
            await message.reply("❌ Foydalanuvchini qo'shishda xatolik yuz berdi.")
    elif message.text == "❌ Yo'q":
        await message.reply("❌ Yangi foydalanuvchi qo'shilmadi.", reply_markup=ReplyKeyboardRemove())
    else:
        await message.reply("❌ Iltimos, tugmalardan birini tanlang.", reply_markup=ReplyKeyboardRemove())
        return
    await state.finish()

@dp.message_handler(commands=['all_orders'])
@admin_only
@restricted_commands_only(['/all_orders'])
async def all_orders_command(message: types.Message):
    """Barcha buyurtmalarni ko'rsatish (faqat admin uchun)."""
    orders = get_all_orders()
    if not orders:
        await message.reply("✅ Hozircha buyurtmalar mavjud emas.")
        return
    response = "📦 **Barcha buyurtmalar:**\n\n"
    current_user = ""
    for order in orders:
        login, full_name, phone_number, telegram_username, role, order_id, products, total_price, payment, remaining_payment, customer_name, customer_surname, order_phone_number, location, detailed_address, delivery_time, order_date = order
        if login != current_user:
            current_user = login
            response += f"**Foydalanuvchi:** @{login} (**FIO:** {full_name}, **Rol:** {role.capitalize()})\n"
        response += (
            f"  **Buyurtma ID:** {order_id}\n"
            f"  **Mahsulotlar:** {products}\n"
            f"  **Umumiy summa:** {total_price:,.0f} so'm\n"
            f"  **To'langan:** {payment:,.0f} so'm\n"
            f"  **Qoldiq:** {remaining_payment:,.0f} so'm\n"
            f"  **Mijoz:** {customer_name} {customer_surname}\n"
            f"  **Telefon:** {order_phone_number}\n"
            f"  **Manzil:** {location} - {detailed_address}\n"
            f"  **Yetkazib berish muddati:** {delivery_time}\n"
            f"  **Buyurtma qilingan sana:** {order_date}\n"
            f"———————————\n"
        )
    await message.reply(response, parse_mode=ParseMode.MARKDOWN)

@dp.message_handler(commands=['kick_user'])
@admin_only
@restricted_commands_only(['/kick_user'])
async def kick_user_command(message: types.Message):
    """Admin tomonidan foydalanuvchini Telegram ID orqali tizimdan chiqarish."""
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply("❌ Iltimos, Telegram ID ni to‘liq kiriting.\nMisol: /kick_user 123456789\n"
                            "Telegram ID ni topish uchun Telegramdan @userinfobot ni foydalaning.")
        return
    
    telegram_id_str = args[1].strip()
    if not telegram_id_str.isdigit():
        await message.reply("❌ Telegram ID faqat raqamlardan iborat bo‘lishi kerak.")
        return

    telegram_id = int(telegram_id_str)
    success = kick_user_by_telegram_id(telegram_id)
    
    if success:
        await message.reply(f"✅ Telegram ID {telegram_id} bilan foydalanuvchi tizimdan chiqarildi.")
        try:
            await bot.send_message(telegram_id, "❌ Sizning akkauntingiz admin tomonidan tizimdan chiqarildi.")
        except Exception as e:
            logger.warning(f"Foydalanuvchiga xabar yuborishda xatolik: {e}")
    else:
        await message.reply(f"❌ Telegram ID {telegram_id} bo‘yicha foydalanuvchi topilmadi yoki chiqarishda xatolik yuz berdi.")

@dp.message_handler(commands=['zakaz'])
@restricted_commands_only(['/zakaz'])
async def zakaz_command(message: types.Message, state: FSMContext):
    """Buyurtma qo'shish jarayonini boshlash."""
    await state.finish()  # Har qanday mavjud holatni tugatadi
    await state.reset_data()  # Holat ma'lumotlarini tozalaydi
    await start_order(message, state=state)

@dp.message_handler(commands=['help'])
@restricted_commands_only(['/help'])
async def help_command_handler(message: types.Message, state: FSMContext):
    """/help komandasini qabul qilish va foydalanuvchidan xabar so'rash."""
    user = get_user_by_telegram_id(message.from_user.id)
    if not user:
        await message.reply("❌ Siz tizimga kirmagansiz. Iltimos, /start buyrug'ini yuboring.")
        return
    await message.reply("📬 Iltimos, adminlarga yuboriladigan xabaringizni kiriting:")
    await HelpProcess.waiting_for_message.set()

# ----------------------------
# 7. HELP HANDLER
# ----------------------------

@dp.message_handler(state=HelpProcess.waiting_for_message)
async def process_help_message(message: types.Message, state: FSMContext):
    """Foydalanuvchi yuborgan yordam xabarini adminlarga yuborish."""
    user = get_user_by_telegram_id(message.from_user.id)
    if not user:
        await message.reply("❌ Siz tizimga kirmagansiz. Iltimos, /start buyrug'ini yuboring.")
        await state.finish()
        return

    user_full_name = user[2]
    user_login = user[1]
    user_message = message.text.strip()

    # Adminlarni olish
    admins = get_admins()
    if not admins:
        await message.reply("❌ Hozircha adminlar mavjud emas.")
        await state.finish()
        return

    # Adminlarga xabar yuborish
    for admin in admins:
        admin_telegram_id = admin[6]
        if admin_telegram_id:
            try:
                await bot.send_message(
                    admin_telegram_id,
                    f"📣 **Foydalanuvchi Yordam So‘radi**\n\n"
                    f"**Login:** @{user_login}\n"
                    f"**FIO:** {user_full_name}\n"
                    f"**Xabar:** {user_message}"
                )
            except Exception as e:
                logger.error(f"❌ Adminga xabar yuborishda xatolik: {e}")

    await message.reply("✅ Xabaringiz adminlarga yuborildi. Tez orada javob olasiz.")
    await state.finish()

# ----------------------------
# 8. ORDER PROCESS HANDLERS
# ----------------------------

async def start_order(message: types.Message, state: FSMContext):
    """Buyurtma jarayonini boshlash."""
    user = get_user_by_telegram_id(message.from_user.id)
    if not user:
        await message.reply("❌ Siz tizimga kirmagansiz. Iltimos, /start buyrug'ini yuboring.")
        return

    data = await state.get_data()
    if 'products' not in data:
        await state.update_data(products=[])

    await message.answer(
        "📦 **Mahsulotni tanlang:**",
        reply_markup=ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True,row_width=4).add(*PRODUCT_PRICES.keys())
    )
    await OrderProcess.product.set()

@dp.message_handler(state=OrderProcess.product)
async def handle_product(message: types.Message, state: FSMContext):
    """Mahsulotni tanlash."""
    product = message.text.strip()
    if product not in PRODUCT_PRICES:
        await message.answer("❌ Iltimos, menyudan mavjud mahsulotni tanlang.")
        return
    # Get existing 'current_product' data
    data = await state.get_data()
    current_product = data.get('current_product', {})
    current_product['name'] = product
    current_product['unit_price'] = PRODUCT_PRICES[product]  # Mahsulotning bir dona narxi

    # Agar mahsulot o'lchami oldindan belgilangan bo'lsa
    if product in PRODUCTS_WITH_FIXED_SIZE:
        current_product['size'] = 'N/A'  # O'lcham yo'q
        await state.update_data(current_product=current_product)
        await message.answer(
            "🔢 **Nechta dona buyurtma bermoqchisiz?**",
            reply_markup=ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add(
                "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"
            )
        )
        await OrderProcess.quantity.set()
    else:
        # Agar mahsulot o'lchami kerak bo'lsa, o'lcham so'raladi
        await state.update_data(current_product=current_product)
        await message.answer(
            "📐 **O'lchamni tanlang:**",
            reply_markup=ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add(*SIZES)
        )
        await OrderProcess.size.set()

@dp.message_handler(lambda message: message.text in SIZES, state=OrderProcess.size)
async def handle_size(message: types.Message, state: FSMContext):
    """Mahsulot o'lchamini tanlash."""
    size = message.text.strip()
    if size == "Nestandart razmer":
        await message.answer(
            "❓ Nestandart o'lchamni shu shablon asosida kiriting: 200x500\nMisol uchun: 200x500 ✅",
            reply_markup=ReplyKeyboardRemove()
        )
        await OrderProcess.custom_size.set()
    else:
        # Update 'size' in 'current_product' without losing 'name'
        data = await state.get_data()
        current_product = data.get('current_product', {})
        current_product['size'] = size
        await state.update_data(current_product=current_product)
        await message.answer(
            "🔢 **Nechta dona buyurtma bermoqchisiz?**",
            reply_markup=ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add(
                "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"
            )
        )
        await OrderProcess.quantity.set()

@dp.message_handler(state=OrderProcess.custom_size)
async def handle_custom_size(message: types.Message, state: FSMContext):
    """Nestandart razmerni qo'lda kiritish va to'g'rilash."""
    size_input = message.text.strip()
    # Replace '-' with 'x' if present
    size_input_corrected = size_input.replace('-', 'x').replace('×', 'x')
    size_parts = size_input_corrected.lower().split('x')
    
    if len(size_parts) == 2 and all(part.isdigit() for part in size_parts):
        size = f"{size_parts[0]}x{size_parts[1]}"
        # Update 'size' in 'current_product' without losing 'name'
        data = await state.get_data()
        current_product = data.get('current_product', {})
        current_product['size'] = size
        await state.update_data(current_product=current_product)
        await message.answer(
            "🔢 **Nechta dona buyurtma bermoqchisiz?**",
            reply_markup=ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add(
                "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"
            )
        )
        await OrderProcess.quantity.set()
    else:
        await message.answer("❌ O'lchamni noto'g'ri kiritdingiz. Iltimos, qayta urinib ko'ring.")

@dp.message_handler(state=OrderProcess.quantity)
async def handle_quantity(message: types.Message, state: FSMContext):
    """Buyurtma miqdorini belgilash va summa hisoblash."""
    if message.text.isdigit():
        quantity = int(message.text)
        if quantity < 1:
            await message.answer("❌ Miqdor kamida 1 bo'lishi kerak. Iltimos, qayta kiriting.")
            return
        data = await state.get_data()
        current_product = data.get('current_product', {})
        product = current_product.get('name')
        size = current_product.get('size', 'N/A')
        if not product:
            await message.reply("❌ Mahsulot tanlanmagan. Iltimos, buyurtma jarayonini qayta boshlang.")
            await state.finish()
            return
        unit_price_per_sq_meter = PRODUCT_PRICES.get(product, 0)
        # Mahsulot o'lchamli va nestandart razmer bo'lsa
        if product not in PRODUCTS_WITH_FIXED_SIZE and size != 'N/A':
            # O'lchamni olish
            try:
                width_cm, length_cm = map(int, size.lower().split('x'))
                # Maydonni hisoblash (kvadrat metrda)
                area = (width_cm * length_cm) / 10000  # sm² ni m² ga aylantirish
                # Umumiy narxni hisoblash
                unit_price = unit_price_per_sq_meter * area
                total_price = unit_price * quantity
            except ValueError:
                await message.answer("❌ O'lcham noto'g'ri formatda. Iltimos, qayta urinib ko'ring.")
                return
        else:
            # Fiks o'lchamli mahsulotlar uchun
            unit_price = unit_price_per_sq_meter
            total_price = unit_price * quantity
        # Yangilash
        current_product['quantity'] = quantity
        current_product['unit_price'] = unit_price  # Bir dona mahsulotning narxi
        current_product['total_price'] = total_price
        await state.update_data(current_product=current_product)
        await message.answer(
            f"💰 **Mahsulot:** {product}\n"
            f"📐 **O'lcham:** {size}\n"
            f"🔢 **Soni:** {quantity}\n"
            f"💰 **Umumiy summa:** {total_price:,.0f} so'm\n\n"
            f"✅ **Summa to'g'rimi?**",
            reply_markup=ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add("✅ Ha", "❌ Yo'q")
        )
        await OrderProcess.confirm_sum.set()
    else:
        await message.answer("❌ Iltimos, faqat raqam kiriting.", reply_markup=ReplyKeyboardRemove())

@dp.message_handler(state=OrderProcess.confirm_sum)
async def confirm_sum(message: types.Message, state: FSMContext):
    """Summa to'g'riligi haqida tasdiqlash."""
    data = await state.get_data()
    if message.text == "✅ Ha":
        products = data.get('products', [])
        current_product = data.get('current_product', {})
        products.append(current_product)
        await state.update_data(products=products, current_product={})
        confirm_markup = ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add("📦 Buyurtma Qo'shish", "✅ Buyurtmani Yakunlash")
        await message.answer(
            "✅ Mahsulot qo'shildi.\n📦 Yana mahsulot qo'shish yoki buyurtmani yakunlashni tanlang:",
            reply_markup=confirm_markup
        )
        await OrderProcess.add_more.set()
    elif message.text == "❌ Yo'q":
        # Yangi narxni kiritishni so'rash
        await message.answer(
            f"❌ {data['current_product']['name']} mahsuloti uchun hozirgi narxi: {data['current_product']['unit_price']:,.0f} so'm.\nO'zgartirish narxini kiriting:",
            reply_markup=ReplyKeyboardRemove()
        )
        await OrderProcess.adjust_price.set()
    else:
        await message.reply("❌ Iltimos, faqat '✅ Ha' yoki '❌ Yo'q' tugmalarini tanlang.")

@dp.message_handler(state=OrderProcess.adjust_price)
async def adjust_price(message: types.Message, state: FSMContext):
    """Mahsulot narxini o'zgartirish."""
    new_price_text = message.text.strip().replace(',', '').replace('.', '')
    if new_price_text.isdigit():
        new_price = int(new_price_text)
        if new_price <= 0:
            await message.answer("❌ Narx ijobiy son bo'lishi kerak. Iltimos, qayta kiriting.")
            return
        data = await state.get_data()
        current_product = data.get('current_product', {})
        unit_price = new_price
        quantity = current_product['quantity']
        total_price = unit_price * quantity
        current_product['unit_price'] = unit_price
        current_product['total_price'] = total_price
        await state.update_data(current_product=current_product)
        await message.answer(
            f"💰 **Mahsulot:** {current_product['name']}\n"
            f"📐 **O'lcham:** {current_product['size']}\n"
            f"🔢 **Soni:** {current_product['quantity']}\n"
            f"💰 **Yangi umumiy summa:** {total_price:,.0f} so'm\n\n"
            f"✅ **Summa to'g'rimi?**",
            reply_markup=ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add("✅ Ha", "❌ Yo'q")
        )
        await OrderProcess.confirm_adjusted_sum.set()
    else:
        await message.answer("❌ Iltimos, faqat raqam kiriting.")

@dp.message_handler(state=OrderProcess.confirm_adjusted_sum)
async def confirm_adjusted_sum(message: types.Message, state: FSMContext):
    """O'zgartirilgan sumni tasdiqlash."""
    data = await state.get_data()
    if message.text == "✅ Ha":
        products = data.get('products', [])
        current_product = data.get('current_product', {})
        products.append(current_product)
        await state.update_data(products=products, current_product={})
        confirm_markup = ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add("📦 Buyurtma Qo'shish", "✅ Buyurtmani Yakunlash")
        await message.answer(
            "✅ Mahsulot qo'shildi.\n📦 Yana mahsulot qo'shish yoki buyurtmani yakunlashni tanlang:",
            reply_markup=confirm_markup
        )
        await OrderProcess.add_more.set()
    elif message.text == "❌ Yo'q":
        # Yana narxni o'zgartirishni taklif qilish
        await message.answer(
            f"❌ {data['current_product']['name']} mahsuloti uchun hozirgi narxi: {data['current_product']['unit_price']:,.0f} so'm.\nO'zgartirish narxini kiriting:",
            reply_markup=ReplyKeyboardRemove()
        )
        await OrderProcess.adjust_price.set()
    else:
        await message.reply("❌ Iltimos, faqat '✅ Ha' yoki '❌ Yo'q' tugmalarini tanlang.")

@dp.message_handler(lambda message: message.text == "📦 Buyurtma Qo'shish", state="*")
async def add_order_button(message: types.Message, state: FSMContext):
    """Buyurtma qo'shish tugmasini bosganda buyurtma jarayonini boshlash."""
    await start_order(message, state=state)

@dp.message_handler(lambda message: message.text == "📄 Buyurtmalarni Ko'rish")
async def view_orders_button(message: types.Message):
    """Buyurtmalarni ko'rish tugmasini bosganda buyurtmalarni ko'rsatish."""
    user = get_user_by_telegram_id(message.from_user.id)
    if not user:
        await message.reply("❌ Siz tizimga kirmagansiz. Iltimos, /start buyrug'ini yuboring.")
        return
    orders = get_user_orders(user[0])
    if not orders:
        await message.reply("📭 Siz hali birorta ham buyurtma bermagansiz.")
        return
    response = "📦 **Sizning buyurtmalaringiz:**\n\n"
    for order in orders:
        order_id, products, total_price, payment, remaining_payment, customer_name, customer_surname, phone_number, location, detailed_address, delivery_time, order_date = order
        response += (
            f"**Buyurtma ID:** {order_id}\n"
            f"**Mahsulotlar:** {products}\n"
            f"**Umumiy summa:** {total_price:,.0f} so'm\n"
            f"**To'langan:** {payment:,.0f} so'm\n"
            f"**Qoldiq:** {remaining_payment:,.0f} so'm\n"
            f"**Mijoz:** {customer_name} {customer_surname}\n"
            f"**Telefon:** {phone_number}\n"
            f"**Manzil:** {location} - {detailed_address}\n"
            f"**Yetkazib berish muddati:** {delivery_time}\n"
            f"**Buyurtma qilingan sana:** {order_date}\n"
            f"———————————\n"
        )
    await message.reply(response, parse_mode=ParseMode.MARKDOWN)

# ----------------------------
# 9. FINALIZE ORDER HANDLER
# ----------------------------

@dp.message_handler(lambda message: message.text == "✅ Buyurtmani Yakunlash", state=OrderProcess.add_more)
async def finalize_order_start(message: types.Message, state: FSMContext):
    """Buyurtmani yakunlash jarayonini boshlash."""
    await message.answer("📛 **Mijozning ismini kiriting:**", reply_markup=ReplyKeyboardRemove())
    await OrderProcess.customer_name.set()

@dp.message_handler(state=OrderProcess.customer_name)
async def get_customer_name(message: types.Message, state: FSMContext):
    """Mijoz ismini qabul qilish."""
    customer_name = message.text.strip()
    if not customer_name:
        await message.reply("❌ Mijoz ismi bo'sh bo'lishi mumkin emas. Iltimos, ismini kiriting.")
        return
    await state.update_data(customer_name=customer_name)
    await message.answer("📛 **Mijozning familiyasini kiriting:**")
    await OrderProcess.customer_surname.set()

@dp.message_handler(state=OrderProcess.customer_surname)
async def get_customer_surname(message: types.Message, state: FSMContext):
    """Mijoz familiyasini qabul qilish."""
    customer_surname = message.text.strip()
    if not customer_surname:
        await message.reply("❌ Mijoz familiyasi bo'sh bo'lishi mumkin emas. Iltimos, familiyasini kiriting.")
        return
    await state.update_data(customer_surname=customer_surname)
    await message.answer("📱 **Mijozning telefon raqamini kiriting misol uchun 123456789/987654321 vaho kazo:**")
    await OrderProcess.phone_number.set()

@dp.message_handler(state=OrderProcess.phone_number)
async def get_customer_phone_number(message: types.Message, state: FSMContext):
    """Mijoz telefon raqamini qabul qilish."""
    phone_number = message.text.strip()
    await state.update_data(phone_number=phone_number)
    await message.answer(
        "🏠 **Mijoz qaysi viloyat yoki shahardan buyurtma qildi?**",
        reply_markup=ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add(
            "Toshkent shahri", "Toshkent viloyati", "Andijon", "Buxoro", "Jizzax", "Qashqadaryo",
            "Navoiy", "Namangan", "Samarqand", "Surxondaryo", "Sirdaryo", "Farg'ona", "Xorazm", "Qoraqalpog'iston"
        )
    )
    await OrderProcess.location.set()


@dp.message_handler(state=OrderProcess.location)
async def get_location(message: types.Message, state: FSMContext):
    """Mijozning viloyati yoki shaharini qabul qilish."""
    location = message.text.strip()
    available_locations = [
        "Toshkent shahri", "Toshkent viloyati", "Andijon", "Buxoro", "Jizzax", "Qashqadaryo",
        "Navoiy", "Namangan", "Samarqand", "Surxondaryo", "Sirdaryo", "Farg'ona", "Xorazm", "Qoraqalpog'iston"
    ]
    if location not in available_locations:
        await message.reply("❌ Iltimos, mavjud variantlardan birini tanlang.")
        return
    await state.update_data(location=location)
    await message.answer("🏡 **Manzilni batafsil kiriting:**")
    await OrderProcess.detailed_address.set()

@dp.message_handler(state=OrderProcess.detailed_address)
async def get_detailed_address(message: types.Message, state: FSMContext):
    """Mijozning manzilini qabul qilish."""
    detailed_address = message.text.strip()
    if not detailed_address:
        await message.reply("❌ Manzil bo'sh bo'lishi mumkin emas. Iltimos, manzilni kiriting.")
        return
    await state.update_data(detailed_address=detailed_address)
    await message.answer(
        "⏰ **Yetkazib berish muddati qachon?** Tanlang yoki kiriting.\n[Bugun] [Ertaga] [Boshqa sana kiritmoqchiman]",
        reply_markup=ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add("Bugun", "Ertaga", "Boshqa sana kiritmoqchiman")
    )
    await OrderProcess.delivery_time.set()

@dp.message_handler(state=OrderProcess.delivery_time)
async def get_delivery_time(message: types.Message, state: FSMContext):
    """Yetkazib berish muddatini qabul qilish."""
    delivery_time = message.text.strip()
    if delivery_time == "Boshqa sana kiritmoqchiman":
        await message.reply("📅 **Yetkazib berish sanasini kiriting:**", reply_markup=ReplyKeyboardRemove())
        await OrderProcess.custom_delivery_date.set()
    elif delivery_time in ["Bugun", "Ertaga"]:
        await state.update_data(delivery_time=delivery_time)
        await show_order_summary(message, state)
    else:
        await message.reply("❌ Iltimos, mavjud variantlardan birini tanlang yoki 'Boshqa sana kiritmoqchiman' ni tanlang.")

@dp.message_handler(state=OrderProcess.custom_delivery_date)
async def get_custom_delivery_date(message: types.Message, state: FSMContext):
    """Foydalanuvchi kiritgan matnni qabul qilish va saqlash."""
    delivery_input = message.text.strip()  # Foydalanuvchidan kiritilgan matnni olish
    await state.update_data(delivery_time=delivery_input)  # Matnni 'delivery_time' kaliti ostida saqlash
    await message.reply(f"✅ Kiritingiz qabul qilindi va saqlandi: '{delivery_input}'")
    await show_order_summary(message, state)  # Buyurtma umumiy ko'rinishini ko'rsatish

async def show_order_summary(message: types.Message, state: FSMContext):
    """Buyurtma ma'lumotlarini ko'rsatish va tasdiqlash."""
    data = await state.get_data()
    products = data.get('products', [])
    total_price = sum([p['total_price'] for p in products])
    customer_name = data.get('customer_name', '')
    customer_surname = data.get('customer_surname', '')
    phone_number = data.get('phone_number', '')
    location = data.get('location', '')
    detailed_address = data.get('detailed_address', '')
    delivery_time = data.get('delivery_time', '')

    # Format products
    products_formatted = "\n".join([f"{idx}. {p['name']} ({p['size']}) - {p['quantity']} ta - {p['unit_price']:,.0f} so'm" for idx, p in enumerate(products, start=1)])

    order_summary = (
        f"📦 **Sizning buyurtmangiz:**\n\n"
        f"**Mahsulotlar:**\n{products_formatted}\n\n"
        f"💰 **Umumiy summa:** {total_price:,.0f} so'm\n"
        f"👤 **Mijoz:** {customer_name} {customer_surname}\n"
        f"📱 **Telefon:** {phone_number}\n"
        f"🏠 **Manzil:** {location} - {detailed_address}\n"
        f"⏰ **Yetkazib berish muddati:** {delivery_time}\n\n"
        f"📜 **Ma'lumotlar to'g'rimi?**"
    )

    confirm_markup = ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True).add("✅ Ha", "❌ Yo'q")
    await message.answer(order_summary, reply_markup=confirm_markup, parse_mode=ParseMode.MARKDOWN)
    await OrderProcess.confirm_order.set()

@dp.message_handler(state=OrderProcess.confirm_order)
async def confirm_order(message: types.Message, state: FSMContext):
    """Buyurtma ma'lumotlarini tasdiqlash."""
    if message.text == "✅ Ha":
        data = await state.get_data()
        user = get_user_by_telegram_id(message.from_user.id)
        if not user:
            await message.reply("❌ Foydalanuvchi topilmadi. Iltimos, /start buyrug'ini yuboring.")
            await state.finish()
            return

        total_price = sum([p['total_price'] for p in data.get('products', [])])
        payment = total_price  # To'liq to'lov qabul qilingan deb hisoblanadi

        success = save_order(
            user_id=user[0],
            products=data.get('products', []),
            total_price=total_price,
            payment=payment,
            customer_name=data.get('customer_name', ''),
            customer_surname=data.get('customer_surname', ''),
            phone_number=data.get('phone_number', ''),
            location=data.get('location', ''),
            detailed_address=data.get('detailed_address', ''),
            delivery_time=data.get('delivery_time', '')
        )
        if success:
            await message.answer("✅ Buyurtma muvaffaqiyatli saqlandi! 😊")
            
            # Adminlarga buyurtma haqida xabar yuborish
            admins = get_admins()
            products_list = "; ".join([
                f"{p['name']} ({p['size']}) - {p['quantity']} ta - {p['unit_price']:,.0f} so'm" 
                for p in data.get('products', [])
            ])
            order_details = (
                f"📦 **Yangi buyurtma keldi:**\n\n"
                f"**Foydalanuvchi:** @{user[1]} (ID: {user[0]})\n"
                f"{products_list}\n"
                f"💰 **Umumiy summa:** {total_price:,.0f} so'm\n"
                f"👤 **Mijoz:** {data.get('customer_name', '')} {data.get('customer_surname', '')}\n"
                f"📱 **Telefon:** {data.get('phone_number', '')}\n"
                f"🏠 **Manzil:** {data.get('location', '')} - {data.get('detailed_address', '')}\n"
                f"⏰ **Yetkazib berish muddati:** {data.get('delivery_time', '')}\n"
                f"📅 **Buyurtma qilingan sana:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
            )

            for admin in admins:
                admin_telegram_id = admin[6]
                if admin_telegram_id:
                    try:
                        await bot.send_message(admin_telegram_id, order_details)
                    except Exception as e:
                        logger.error(f"❌ Adminga buyurtma yuborishda xatolik: {e}")
            
            # Present the main action buttons again
            user_buttons = ReplyKeyboardMarkup(
                resize_keyboard=True, 
                one_time_keyboard=True
            ).add("📦 Buyurtma Qo'shish", "📄 Buyurtmalarni Ko'rish")
            
            await message.answer(
                "📦 **Yana buyurtma qo'shish yoki buyurtmalarni ko'rishni tanlang:**",
                reply_markup=user_buttons
            )
            await state.finish()
        else:
            await message.answer("❌ Buyurtmani saqlashda xatolik yuz berdi. Iltimos, qayta urinib ko'ring.")
            await state.finish()
    elif message.text == "❌ Yo'q":
        # Present the main action buttons without saving the order
        user_buttons = ReplyKeyboardMarkup(
            resize_keyboard=True, 
            one_time_keyboard=True
        ).add("📦 Buyurtma Qo'shish", "📄 Buyurtmalarni Ko'rish")
        
        await message.answer(
            "❌ Buyurtma saqlanmadi.\n📦 Yana buyurtma qo'shishni yoki buyurtmalarni ko'rishni tanlang:",
            reply_markup=user_buttons
        )
        await state.finish()
    else:
        await message.reply("❌ Iltimos, faqat '✅ Ha' yoki '❌ Yo'q' tugmalarini tanlang.")

@dp.message_handler(state=OrderProcess.add_more)
async def ask_add_more(message: types.Message, state: FSMContext):
    """Yana buyurtma qo'shish yoki yakunlashni so'rash."""
    if message.text == "📦 Buyurtma Qo'shish":
        await start_order(message, state=state)
    elif message.text == "✅ Buyurtmani Yakunlash":
        await finalize_order_start(message, state=state)
    else:
        await message.reply("❌ Iltimos, tugmalardan birini tanlang.")

# ----------------------------
# 10. UNKNOWN COMMAND HANDLER
# ----------------------------

@dp.message_handler(lambda message: message.text.startswith('/') and message.text.split()[0] not in ['/start', '/admin', '/my_orders', '/add_user', '/all_orders', '/kick_user', '/zakaz', '/help'])
async def unknown_command(message: types.Message):
    """Noma'lum komandalarni javoblash."""
    await message.reply("❌ Bu komanda ruxsat etilmagan yoki mavjud emas.")

# ----------------------------
# 11. DEFAULT COMMANDS SETTING
# ----------------------------

async def set_default_commands():
    """Bot uchun standart komandalarni belgilash."""
    user_commands = [
        types.BotCommand(command="/start", description="Botni boshlash"),
        types.BotCommand(command="/zakaz", description="Yangi buyurtma qo'shish"),
        types.BotCommand(command="/my_orders", description="O'z buyurtmalarini ko'rish"),
        types.BotCommand(command="/admin", description="Admin sifatida kirish"),
        types.BotCommand(command="/add_user", description="Yangi foydalanuvchi qo'shish (Admin)"),
        types.BotCommand(command="/all_orders", description="Barcha buyurtmalarni ko'rish (Admin)"),
        types.BotCommand(command="/kick_user", description="Foydalanuvchini chiqarish (Admin)"),
        types.BotCommand(command="/help", description="Adminlarga yordam so'rash")
    ]

    await bot.set_my_commands(user_commands)
    logger.info("✅ User commands have been set.")

# ----------------------------
# 12. NOTIFY ADMINS OF LOGIN
# ----------------------------

async def notify_admins_of_login(user: tuple):
    """Har qanday foydalanuvchi tizimga kirganda barcha adminlarga xabar yuboradi."""
    role = user[5].capitalize()  # 'admin' yoki 'sotuvchi'
    telegram_id = user[6]
    telegram_username = user[7] if user[7] else "N/A"

    # Mapping 'sotuvchi' to 'User' for clarity
    account_type = "Admin" if role.lower() == 'admin' else "Sotuvchi"

    # To avoid '@N/A', adjust the username display
    if telegram_username != "N/A":
        telegram_username_display = f"@{telegram_username}"
    else:
        telegram_username_display = "N/A"

    message_text = (
        f"📢 **YANGI LOGIN:**\n\n"
        f"**AKKAUNT:** {account_type}\n"
        f"**Telegram ID:** {telegram_id}\n"
        f"**Telegram Username:** {telegram_username_display}"
    )

    admins = get_admins()
    if not admins:
        logger.warning("❌ Adminlar topilmadi. Xabar yuborilmadi.")
        return

    for admin in admins:
        admin_telegram_id = admin[6]
        if admin_telegram_id:
            try:
                await bot.send_message(admin_telegram_id, message_text)
            except Exception as e:
                logger.error(f"❌ Adminga login haqida xabar yuborishda xatolik: {e}")

# ----------------------------
# 13. MAIN
# ----------------------------

if __name__ == "__main__":
    init_db()
    if len(sys.argv) > 1:
        if sys.argv[1] == 'run_create_admin':
            create_admin()
        elif sys.argv[1] == 'run':
            async def on_startup(dispatcher: Dispatcher):
                await set_default_commands()
                logger.info("✅ Bot ishga tushdi va komandalar belgilandi.")
            executor.start_polling(dp, skip_updates=True, on_startup=on_startup)
        else:
            print("❌ Noto'g'ri argument. Botni ishga tushirish uchun 'python bot.py run' yoki admin yaratish uchun 'python bot.py run_create_admin' ni kiriting.")
    else:
        print("❌ Argument kiritilmagan. Botni ishga tushirish uchun 'python bot.py run' yoki admin yaratish uchun 'python bot.py run_create_admin' ni kiriting.")
