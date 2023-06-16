
# Flask utils
from flask import Flask, request, render_template,redirect, url_for, request
from werkzeug.utils import secure_filename
import mysql.connector
import pandas as pd
import itertools
from sklearn.metrics import classification_report,confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
import sklearn.metrics as metrics
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import xgboost as xgb
from lightgbm import LGBMClassifier
import os
import seaborn as sns
#from wordcloud import WordCloud
import re
from urllib.parse import urlparse
from tld import get_tld
from urllib.parse import urlparse
from googlesearch import search
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
import csv
from collections import Counter

# Define a flask app
app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method=='POST':
        print("hai")
        uname=request.form['uname']
        pwd=request.form['pwd']
        addr=request.form['addr']
        email=request.form['email']
        mno=request.form['mno']

        mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            passwd="",
            database="malicious"
        )
        mycursor = mydb.cursor()

        sql = "INSERT INTO regist VALUES (%s,%s,%s,%s,%s)"
        val = (uname,pwd,addr,email,mno)
        mycursor.execute(sql, val)
        mydb.commit()
        return render_template('index.html')
        print("Successfully Registered")

    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    global name, password
    global user
    if request.method == "POST":
        username = request.form['uname']
        password1 = request.form['pwd']
        mydb = mysql.connector.connect(host="localhost", user="root", passwd="", database="malicious")
        cursor = mydb.cursor()
        sql = "select * from regist where email='%s' and pwd='%s'" % (username, password1)
        print('q')
        x = cursor.execute(sql)
        print(x)
        results = cursor.fetchall()
        print(results)
        if len(results) > 0:
            print('r')
            # session['user'] = username
            # session['id'] = results[0][0]
            # print(id)
            # print(session['id'])
            return render_template('userhome.html', msg="Login Success")
        else:
            return render_template('login.html', msg="Login Failure!!!")

    return render_template("login.html")

@app.route("/userhome")
def userhome():
    return render_template("userhome.html")



# def get_prediction_from_url(test_url):
#     features_test = main(test_url)
#     # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
#
#     features_test = np.array(features_test).reshape((1, -1))
#     pred = lgb.predict(features_test)
#     if int(pred[0]) == 0:
#
#         res = "SAFE"
#         return res
#     elif int(pred[0]) == 1.0:
#
#         res = "DEFACEMENT"
#         return res
#     elif int(pred[0]) == 2.0:
#         res = "PHISHING"
#         return res
#
#     elif int(pred[0]) == 3.0:
#
#         res = "MALWARE"
#         return res

@app.route('/process', methods=['GET', 'POST'])
def process():
    if request.method=='POST':
        df = pd.read_csv('malicious_phish.csv')
        df.head()

        df['use_of_ip'] = df['url'].apply(lambda i: having_ip_address(i))
        df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))
        df['google_index'] = df['url'].apply(lambda i: google_index(i))
        df['count.'] = df['url'].apply(lambda i: count_dot(i))
        df['count-www'] = df['url'].apply(lambda i: count_www(i))
        df['count@'] = df['url'].apply(lambda i: count_atrate(i))
        df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))
        df['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed(i))
        df['short_url'] = df['url'].apply(lambda i: shortening_service(i))
        df['count-https'] = df['url'].apply(lambda i: count_https(i))
        df['count-http'] = df['url'].apply(lambda i: count_http(i))
        df['count%'] = df['url'].apply(lambda i: count_per(i))
        df['count?'] = df['url'].apply(lambda i: count_ques(i))
        df['count-'] = df['url'].apply(lambda i: count_hyphen(i))
        df['count='] = df['url'].apply(lambda i: count_equal(i))
        df['url_length'] = df['url'].apply(lambda i: url_length(i))
        df['hostname_length'] = df['url'].apply(lambda i: hostname_length(i))
        df['count-digits'] = df['url'].apply(lambda i: digit_count(i))
        df.head()
        df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))
        df['count-letters'] = df['url'].apply(lambda i: letter_count(i))
        df['fd_length'] = df['url'].apply(lambda i: fd_length(i))
        df['tld'] = df['url'].apply(lambda i: get_tld(i, fail_silently=True))
        df['tld_length'] = df['tld'].apply(lambda i: tld_length(i))
        lb_make = LabelEncoder()
        df["type_code"] = lb_make.fit_transform(df["type"])
        X = df[['use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
                'count_dir', 'count_embed_domian', 'short_url', 'count-https',
                'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
                'hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits',
                'count-letters']]
        # Target Variable
        y = df['type_code']
        X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, shuffle=True,
                                                            random_state=5)
        rf = RandomForestClassifier(n_estimators=100, max_features='sqrt')
        rf.fit(X_train, y_train)
        y_pred_rf = rf.predict(X_test)

        print("RandomForestClassifier")
        print("----------------------")
        print(classification_report(y_test, y_pred_rf, target_names=['benign', 'defacement', 'phishing', 'malware']))
        score = metrics.accuracy_score(y_test, y_pred_rf)
        print("accuracy:   %0.3f" % score)

        print("XGBClassifier")
        print("-------------")
        xgb_c = xgb.XGBClassifier(n_estimators=100)
        xgb_c.fit(X_train, y_train)
        y_pred_x = xgb_c.predict(X_test)
        print(classification_report(y_test, y_pred_x, target_names=['benign', 'defacement', 'phishing', 'malware']))
        score = metrics.accuracy_score(y_test, y_pred_x)
        print("accuracy:   %0.3f" % score)

        lgb = LGBMClassifier(objective='multiclass', boosting_type='gbdt', n_jobs=5,
                             silent=True, random_state=5)
        LGB_C = lgb.fit(X_train, y_train)
        y_pred_lgb = LGB_C.predict(X_test)

        print("LGBMClassifier")
        print("---------------")
        print(classification_report(y_test, y_pred_lgb, target_names=['benign', 'defacement', 'phishing', 'malware']))
        score = metrics.accuracy_score(y_test, y_pred_lgb)
        print("accuracy:   %0.3f" % score)


        # urls = ['titaniumcorporate.co.za', 'en.wikipedia.org/wiki/North_Dakota']
        # for url in urls:
        #
        #     features_test = main(url)
        #     # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
        #
        #     features_test = np.array(features_test).reshape((1, -1))
        #     pred = lgb.predict(features_test)
        #     if int(pred[0]) == 0:
        #         res = "SAFE"
        #     elif int(pred[0]) == 1.0:
        #         res = "DEFACEMENT"
        #     elif int(pred[0]) == 2.0:
        #         res = "PHISHING"
        #     elif int(pred[0]) == 3.0:
        #         res = "MALWARE"
        #
        #     print(res)
            # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.

        return render_template('process.html')

    return render_template("process.html")

@app.route('/process1', methods=['GET', 'POST'])
def process1():
    if request.method == 'POST':

        df = pd.read_csv('malicious_phish.csv')
        df.head()
        df['use_of_ip'] = df['url'].apply(lambda i: having_ip_address(i))
        df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))
        df['google_index'] = df['url'].apply(lambda i: google_index(i))
        df['count.'] = df['url'].apply(lambda i: count_dot(i))
        df['count-www'] = df['url'].apply(lambda i: count_www(i))
        df['count@'] = df['url'].apply(lambda i: count_atrate(i))
        df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))
        df['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed(i))
        df['short_url'] = df['url'].apply(lambda i: shortening_service(i))
        df['count-https'] = df['url'].apply(lambda i: count_https(i))
        df['count-http'] = df['url'].apply(lambda i: count_http(i))
        df['count%'] = df['url'].apply(lambda i: count_per(i))
        df['count?'] = df['url'].apply(lambda i: count_ques(i))
        df['count-'] = df['url'].apply(lambda i: count_hyphen(i))
        df['count='] = df['url'].apply(lambda i: count_equal(i))
        df['url_length'] = df['url'].apply(lambda i: url_length(i))
        df['hostname_length'] = df['url'].apply(lambda i: hostname_length(i))
        df['count-digits'] = df['url'].apply(lambda i: digit_count(i))
        df.head()
        df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))
        df['count-letters'] = df['url'].apply(lambda i: letter_count(i))
        df['fd_length'] = df['url'].apply(lambda i: fd_length(i))
        df['tld'] = df['url'].apply(lambda i: get_tld(i, fail_silently=True))
        df['tld_length'] = df['tld'].apply(lambda i: tld_length(i))
        lb_make = LabelEncoder()
        df["type_code"] = lb_make.fit_transform(df["type"])
        X = df[['use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
            'count_dir', 'count_embed_domian', 'short_url', 'count-https',
            'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
            'hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits',
            'count-letters']]
        y = df['type_code']
        X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, shuffle=True,
                                                        random_state=5)
        urls = ['titaniumcorporate.co.za', 'en.wikipedia.org/wiki/North_Dakota']
        lgb = LGBMClassifier(objective='multiclass', boosting_type='gbdt', n_jobs=5,
                         silent=True, random_state=5)
        LGB_C = lgb.fit(X_train, y_train)
        y_pred_lgb = LGB_C.predict(X_test)
        url=request.form['i']
        features_test = main(url)
        features_test = np.array(features_test).reshape((1, -1))
        pred = lgb.predict(features_test)
        print(len(url))
        if(len(url)==0):
            res = "input"
        else:
            if int(pred[0]) == 0:
                res = "SAFE"
            elif int(pred[0]) == 1.0:
                res = "DEFACEMENT"
            elif int(pred[0]) == 2.0:
                res = "PHISHING"
            elif int(pred[0]) == 3.0:
                res = "MALWARE"

        return render_template("process1.html",result=res)


    return render_template("process1.html")
@app.route('/process', methods=['GET', 'POST'])
def having_ip_address(url):

    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

@app.route('/process', methods=['GET', 'POST'])
def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

@app.route('/process', methods=['GET', 'POST'])
def google_index(url):
    site = search(url, 5)
    return 1 if site else 0

@app.route('/process', methods=['GET', 'POST'])
def count_dot(url):
    count_dot = url.count('.')
    return count_dot

@app.route('/process', methods=['GET', 'POST'])
def count_www(url):
    url.count('www')
    return url.count('www')

@app.route('/process', methods=['GET', 'POST'])
def count_atrate(url):
    return url.count('@')

@app.route('/process', methods=['GET', 'POST'])
def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

@app.route('/process', methods=['GET', 'POST'])
def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

@app.route('/process', methods=['GET', 'POST'])
def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0

@app.route('/process', methods=['GET', 'POST'])
def count_https(url):
    return url.count('https')

@app.route('/process', methods=['GET', 'POST'])
def count_http(url):
    return url.count('http')

@app.route('/process', methods=['GET', 'POST'])
def count_per(url):
    return url.count('%')

@app.route('/process', methods=['GET', 'POST'])
def count_ques(url):
    return url.count('?')

@app.route('/process', methods=['GET', 'POST'])
def count_hyphen(url):
    return url.count('-')

@app.route('/process', methods=['GET', 'POST'])
def count_equal(url):
    return url.count('=')

@app.route('/process', methods=['GET', 'POST'])
def url_length(url):
    return len(str(url))

@app.route('/process', methods=['GET', 'POST'])
def hostname_length(url):
    return len(urlparse(url).netloc)

@app.route('/process', methods=['GET', 'POST'])
def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0

@app.route('/process', methods=['GET', 'POST'])
def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

@app.route('/process', methods=['GET', 'POST'])
def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

@app.route('/process', methods=['GET', 'POST'])
def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

@app.route('/process', methods=['GET', 'POST'])
def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

@app.route('/process', methods=['GET', 'POST'])
def main(url):
    status = []

    status.append(having_ip_address(url))
    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    status.append(count_atrate(url))
    status.append(no_of_dir(url))
    status.append(no_of_embed(url))

    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))

    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    status.append(url_length(url))
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(fd_length(url))
    tld = get_tld(url, fail_silently=True)

    status.append(tld_length(tld))

    return status

@app.route('/graph', methods=['GET', 'POST'])
def graph():
    cc1 = 0
    cc2 = 0
    cc3 = 0
    cc4 = 0
    # with open('malicious_phish.csv', 'rt')as f:
    #     data = csv.reader(f)
        # for row in data:
        #     print(cc1,cc2,cc3,cc4)
        #     print(row[0]+":"+row[1])
        #     r=str(row[1]).replace(" ", "")
        #     print(r)
        #     if (r.find("benign")):
        #         cc1 =cc1+1
        #     elif (r.find("defacement")):
        #         cc2 =cc2+1
        #     elif (r.find("phishing")):
        #         cc3 =cc3+1
        #     elif (r.find("malware")):
        #         cc4 =cc4+1

    words = []
    with open('malicious_phish.csv', 'rt') as f:
        data = csv.reader(f)
        for row in data:
            words = row[1]
            cc1+=words.count("benign")
            cc2 += words.count("defacement")
            cc3 += words.count("phishing")
            cc4 += words.count("malware")
        # words_counted = []
        # for i in words:
        #     x = words.count(i)
        #     words_counted.append((i, x))

    # print(words_counted)
    print(cc1,cc2,cc3,cc4)
    line_labels = ["benign","defacement","phishing","malware"]
    line_values = [cc1,cc2,cc3,cc4]
    return render_template('graph.html', title='URL CLASSIFICATION', max=17000, labels=line_labels,
                           values=line_values)
if __name__ == '__main__':
    app.run(debug=False)


