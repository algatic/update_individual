import re
from logging import exception

from pymongo import MongoClient, UpdateOne
import datetime

from datetime import datetime, timezone, timedelta
import pytz
import schedule

import threading
import time

import sys

# 打开一个文件以进行写入（会覆盖原有内容）

# 连接到MongoDB

uri = f'mongodb://{username}:{password}@{host}:{port}'  
client_b = MongoClient(uri)
vuln_names = ['go', 'maven', 'npm', 'nuget', 'pypi', 'pub', 'Ruby']

def convert_to_timestamp(time_str,name, source):
    if not time_str:
        #print('Invalid input: empty string')
        return 0
    #print(time_str)
    # 定义三种时间格式
    time_format_1 = "%Y-%m-%dT%H:%M:%S.%f%z"  # 包含微秒和时区
    time_format_2 = "%Y-%m-%dT%H:%M:%SZ"  # 不含微秒的UTC时间
    time_format_3 = "%Y-%m-%dT%H:%M:%S"  # 不含微秒和时区

    try:
        # 尝试解析不含时区和微秒的格式
        try:
            dt_obj = datetime.strptime(time_str, time_format_3)
            #print('Parsed with format 3')
            # 假设时间为 UTC 时间
            if dt_obj.year < 1970 or dt_obj.year > datetime.now().year:
                return 0
            dt_obj = dt_obj.replace(tzinfo=timezone.utc)
            return dt_obj.timestamp()
        except ValueError:
            pass  # 如果格式不匹配，尝试下一种格式

        # 尝试解析不含微秒但带 UTC 时区的格式
        try:
            dt_obj = datetime.strptime(time_str, time_format_2)
            #print('Parsed with format 2')
            if dt_obj.year < 1970 or dt_obj.year > datetime.now().year:
                return 0
            return dt_obj.timestamp()
        except ValueError:
            pass

        # 尝试解析带微秒和时区的格式
        if '.' not in time_str:
            time_str = time_str[:-6] + '.000000' + time_str[-6:]

        try:
            dt_obj = datetime.strptime(time_str, time_format_1)
            if dt_obj.year < 1970 or dt_obj.year > datetime.now().year:
                return 0
            #print('Parsed with format 1')
            return dt_obj.timestamp()
        except ValueError:
            print('Failed to parse time string')
            return 0

    except Exception as e:
        # 捕获任何其他异常
        print(f"Error: {e},{name},{source}")
        return 0

doc_infos = {
    "cargo": ('updated_time'), #0意味着递减，后面是字段名
    "clojars": ('created_time'),
    "go": ('published_at'),
    'maven':('published_at'),
    'npm':('published_time'),
    'nuget':('published_at'),
    'Perl':('published_time'),
    'pub':('published'),
    'pypi':(None),
    'Ruby':('published_time')
}

def query_table_info(table_name):
    global doc_infos
    table_info = doc_infos.get(table_name)
    if table_info:
        return table_info  # 返回一个元组 (顺序, 字段名列表)
    else:
        return None  # 表名不存在时返回 None


col_a = db_a['software_individual']
col_c = db_a['software_individual_test']
db_github = client_b['github']
col_d = db_github['stars_packages']
col_e = db_github['prs']
#col_vuln = db_a['mongo_pkg_with_vuls']
col_version = db_a['software_version_saved']

#gap_time = 2000000 #8640000

def docu_get(origin_col, target_col,doc_name,std_time):
    global z, y, gap_time, doc_infos
    #v_attr = query_table_info(doc_name)
    if True:
        database_name = doc_name
        db_b = client_b[database_name.lower()]
        col_b = db_b['packages']
        if doc_name in vuln_names:
            col_vuln = db_b['vuls']
        i = 0
        #print(i, datetime.now())
        # j是已读的项数
        batch_size = 3000
        query = {'data_update_time': {'$gte': std_time}}  # 假设你要筛选 age 字段大于 30 的文档
        cursor = col_b.find(query)  # 获取游标
        cursor.batch_size(batch_size)
        for document in cursor:
            i = i + 1
            #print(i, datetime.datetime.now())
            '''if i < 10833 and doc_name is 'pypi':
                continue'''
            '''if document['data_update_time'] < std_time:
                continue'''
            #print(name, document.get('name'))
            #print(i, document.get('name'), datetime.now())
            # print(b_data)
            #b_data = [document]
            # 创建一个字典以便快速查找
            versions_origin = document.get('versions')
            proj_name = document.get('name')
            if doc_name is 'Perl' or doc_name is 'Ruby':
                query_version = {
                    'proj_name': proj_name,  # proj_name 字段必须等于 proj_name
                    'proj_lang': database_name
                }
            else:
                query_version = {
                    'proj_name': proj_name,  # proj_name 字段必须等于 proj_name
                    'proj_source': database_name
                }
            if versions_origin:
                #print(v_attr)
                '''if v_attr:
                    versions = [data for version, data in versions_origin.items() if convert_to_timestamp(data.get(v_attr),proj_name,doc_name) > (std_time-gap_time)]
                    for version, data in versions_origin.items():
                        #print(data.get(v_attr),convert_to_timestamp(data.get(v_attr)))
                else:
                    #print("1")
                    versions = [
                        data for version, data in versions_origin.items()
                        if any(
                            isinstance(release, dict) and release.get('upload_time')
                            #and print(f"upload_time: {release.get('upload_time')} {convert_to_timestamp(release.get('upload_time'))}") is None
                            and convert_to_timestamp(release.get('upload_time'),proj_name,doc_name) > (std_time - gap_time)
                            for release in data.get("release_list", [])
                        )
                    ]'''

                versions_saved_data = col_version.find(query_version)
                versions = []
                if versions_saved_data:
                    versions_all = []
                    for version_saved_data in versions_saved_data:
                        versions_saved = version_saved_data.get('proj_versions')
                        versions_all.extend(versions_saved)
                    #print(proj_name,versions_all)
                    versions = [data for version, data in versions_origin.items() if data.get('version') not in versions_all]
                for value in versions:
                    version = value.get('version')
                    #print(version)
                    match = origin_col.count_documents(
                        {'proj_name': proj_name, 'proj_version': version, 'proj_source': doc_name})
                    if doc_name == 'Ruby' or doc_name == 'Perl':
                        match = origin_col.count_documents(
                            {'proj_name': proj_name, 'proj_version': version, 'proj_lang': doc_name})
                    if match != 0:
                        print("test及原表不匹配情况：", doc_name, proj_name, version, match)
                    if True:
                        update_field = {
                            'insert_time': datetime.now(),
                            'insert_source': f'mongo_{doc_name}',
                            'std_purl': f'{doc_name}/{proj_name}@{version}',
                            'proj_name': proj_name,
                            'proj_version': version,
                            'proj_source': doc_name
                        }
                        if doc_name == 'Ruby' or doc_name == 'Perl':
                            update_field = {
                                'insert_time': datetime.now(),
                                'insert_source': f'mongo_{doc_name}',
                                'std_purl': f'{doc_name}/{proj_name}@{version}',
                                'proj_name': proj_name,
                                'proj_version': version,
                                'proj_lang': doc_name
                            }
                        if doc_name in vuln_names:
                            result = col_vuln.find_one({'pkg_name': proj_name}, {'vul': 1})
                            vuls = None
                            if result:
                                vuls = result.get('vul')
                            if vuls:
                                #print('vul appear')
                                update_field = {
                                    'insert_time': datetime.now(),
                                    'insert_source': f'mongo_{doc_name}',
                                    'std_purl': f'{doc_name}/{proj_name}@{version}',
                                    'proj_name': proj_name,
                                    'proj_version': version,
                                    'proj_source': doc_name,
                                    'proj_vuln': vuls
                                }
                                if doc_name == 'Ruby' or doc_name == 'Perl':
                                    update_field = {
                                        'insert_time': datetime.now(),
                                        'insert_source': f'mongo_{doc_name}',
                                        'std_purl': f'{doc_name}/{proj_name}@{version}',
                                        'proj_name': proj_name,
                                        'proj_version': version,
                                        'proj_lang': doc_name,
                                        'proj_vuln': vuls
                                    }
                        keys_to_update_outside = {
                            'proj_desc': 'description',#需要新加，all
                            'proj_kywrds': 'keywords',
                            'homepage_link': 'homepage',
                            'proj_owner': 'owner',
                            'homepage_link': 'project_url',
                            'org_info': 'owner_team',
                            'proj_repo': 'repository_url',
                            'lcs_name': 'licenses'
                        }
                        # print(download_link,dpdnc_version)
                        # print(value)
                        for mongo_field, source_field in keys_to_update_outside.items():
                            if source_field in document:
                                update_field[mongo_field] = document[source_field]
                        # 只在 b_data 中存在的键进行赋值
                        keys_to_update_inside = {
                            'proj_version_release': 'release_list',
                            'mtnr_info': 'maintainers',
                            'mtnr_info': 'maintainer',
                            'author_info': 'author',
                            'version_lines_num': 'lines_of_codes',
                            'proj_desc': 'description',#新加，for clojar
                            'proj_repo': 'url',#同上
                            'download_link': 'archive_url',
                            'download_link': 'gem_url',
                            'download_link': 'download_url',
                            'download_link': 'tarball',
                            'dpdnc_version': 'dependencies',
                            'proj_readme': 'readme_path',
                            'proj_version_release': 'release_list',
                            'function_provided': 'provides',
                            'proj_main_module': 'main_module',
                        }
                        # print(download_link,dpdnc_version)
                        # print(value)
                        for mongo_field, source_field in keys_to_update_inside.items():
                            if source_field in value:
                                update_field[mongo_field] = value[source_field]
                        # print("0")
                        # print(update_field)
                        target_col.insert_one(
                            update_field
                        )
                    col_version.update_one(query_version, {"$push": {"proj_versions": version},
                                                          "$set": {"update_time": document.get('data_update_time')}},upsert=True)

def docu_update(origin_col, info_col):
    n = 0
    repo_info = True
    updated_list = []
    def reg_url(url):
        pattern = r"github\.com/([^/]+)/([^/]+)"
        match = re.search(pattern,url)
        if match:
            return f"{match.group(1)}/{match.group(2)}"
        else:
            return None

    for doc in origin_col.find():
        n = n + 1
        '''if n<15045623:
            continue'''
        if 'proj_repo' in doc:
            re_repo = reg_url(doc['proj_repo'])
            #print(re_repo,updated_list)
            if re_repo in updated_list:
                #print('skipped')
                continue
            else:
                updated_list.append(re_repo)
            #print(re_repo)
        if 'homepage_link' in doc:
            re_hp = reg_url(doc['homepage_link'])
            if re_hp in updated_list:
                #print('skipped')
                continue
            else:
                updated_list.append(re_hp)
            #print(re_hp)
        print(n, doc['proj_name'])
        if 'proj_repo' in doc and 'github' in doc['proj_repo']:
            #print('inside','github' in doc['proj_repo'],doc['proj_repo'])
            if info_col.count_documents({'full_name': re_repo}) > 0:
                match_item = re_repo
                value = info_col.find_one({'full_name':match_item})
                #print(match_item)
                updated_list.append(re_repo)
                repo_info = True
            else:
                continue
        elif 'homepage_link' in doc and info_col.count_documents({'full_name':re_hp})>0 and 'github' in doc['homepage_link']:
            if info_col.count_documents({'full_name': re_hp}) > 0:
                match_item = re_hp
                value = info_col.find_one({'full_name': match_item})
                #print(match_item)
                updated_list.append(re_hp)
                repo_info = False
            else:
                continue
        else:
            continue
        update_field = {
            'update_time': datetime.now()
        }
        keys_to_update = {
            'commit_info': 'commits',
            'comment_info': 'comments',
            'participant_info': 'participants',
            'review_info': 'reviews',
            'star_num': 'starNum',
            'fork_num': 'forkNum',
            'download_link': 'download_url',
            'contributor_sum': 'committersNum',
            'cmt_sum': 'commitNum',
            'cmt_month': 'last30DaysCommitNum',
            'latest_cmt_time': 'latestCommitNum',
            'all_lines_num': 'lines_of_codes',
            'latest_version_update_time': 'latestCommitTime',
            'first_cmt_time': 'createdAt',
            'lcs_name': 'license',
            'dpdnc_pkg': 'dependencies',
            'proj_owner': 'owner',
            'org_info': 'organization',
            'lang_ratio': 'language'
        }
        for mongo_field, source_field in keys_to_update.items():
            if source_field in value:
                update_field[mongo_field] = value[source_field]
        if repo_info:
            result = origin_col.update_many(
                {
                    'proj_repo': doc['proj_repo']
                },
                {
                    '$set': update_field
                }
            )
        else:
            result = origin_col.update_many(
                {
                    'homepage_link': doc['homepage_link']
                },
                {
                    '$set': update_field
                }
            )
        '''if result.modified_count > 0:
            #print("更新了",match_item,"成功更新的数量：", result.modified_count)'''

def full_docu_wb(source_col, target_col):
    print('start read')
    batch_size = 3000
    cursor = source_col.find().batch_size(batch_size)

    # 计时开始
    start_time = time.time()

    # 初始化批次操作
    operations = []
    count = 0  # 记录操作次数

    for doc in cursor:
        # 为每条数据创建更新操作
        operations.append(UpdateOne({'_id': doc['_id']}, {'$set': doc}, upsert=True))
        count += 1

        # 每处理完一批次，就执行一次批量写入操作
        if count % batch_size == 0:
            # 执行批量操作
            target_col.bulk_write(operations)
            print(f"Transferred {count} documents in this batch.")
            operations.clear()  # 清空操作列表，准备处理下一批

    # 处理最后剩余的数据（如果有的话）
    if operations:
        target_col.bulk_write(operations)
        print(f"Transferred remaining {len(operations)} documents.")

    return count

def check_and_delete(col_c, col_a):
    # 查询 col_c 中的所有文档
    col_c_documents = col_c.find()

    # 检查 col_a 是否包含 col_c 中的所有文档
    all_contained = True
    for doc in col_c_documents:
        # 检查 col_a 中是否存在与 col_c 中相同的文档
        if col_a.count_documents({'_id': doc['_id']}) == 0:
            all_contained = False
            break

    # 如果 col_a 包含 col_c 中的所有文档，则删除 col_c 中的文档
    if all_contained:
        print("col_a contains all documents of col_c. Deleting col_c.")
        col_c.delete_many({})  # 删除 col_c 中的所有文档
    else:
        print("col_a does not contain all documents of col_c.")

def main(std_time):
    # 定义一个函数来处理docu_get任务
    def task_docu_get(key):
        docu_get(col_a, col_c, key, std_time)

    # 创建线程池，执行docu_get任务并行处理
    docu_get_threads = []
    for key in doc_infos:
        thread = threading.Thread(target=task_docu_get, args=(key,))
        docu_get_threads.append(thread)
        thread.start()
        print(f'get {key} start')

    # 等待所有docu_get任务完成
    th_mark = 0
    for thread in docu_get_threads:
        thread.join()
        th_mark = th_mark + 1
        print(f'finish {th_mark} source')

    def task_1():
        print("Task 1 started")
        docu_update(col_c, col_e)  # 模拟任务耗时
        print("Task 1 completed")

    def task_2():
        print("Task 2 started")
        docu_update(col_c, col_e)  # 模拟任务耗时
        print("Task 2 completed")

    # 启动docu_update任务的线程
    thread_1 = threading.Thread(target=task_1)
    thread_2 = threading.Thread(target=task_2)

    thread_1.start()
    thread_2.start()

    # 等待两个docu_update任务完成
    thread_1.join()
    thread_2.join()

    # 执行full_docu_wb任务
    cnt = full_docu_wb(col_c, col_a)
    check_and_delete(col_c, col_a)

    return cnt

def task():
    last_time = time.time()-86400
    start_time = time.time()

    cnt = main(last_time)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"The loop ran for {elapsed_time:.4f} seconds.")

    '''line = f'{datetime.now()} : {cnt} {elapsed_time}s'
    with open(f"D:\\isrc\\组件信息表输出\\{start_time}_daily_data.txt", "w", encoding="utf-8") as file:
        file.write(line + "\n")'''

if __name__ == '__main__':
    #std_time = int(time.time())
    #需要记录上次执行的
    '''current_time = datetime.now()

    # 定义任务的开始时间（例如从当前时间开始，或者自定义一个开始时间）
    start_time = datetime(current_time.year, current_time.month, current_time.day, 0, 0, 0)

    # 如果当前时间已经过了午夜零点，可以设置为第二天的午夜
    if current_time > start_time:
        start_time += timedelta(days=1)

    # 计算当前时间到下一个午夜零点的间隔
    time_to_wait = (start_time - current_time).total_seconds()

    # 等待直到午夜零点
    print(f"Waiting until {start_time} to start the task.")
    time.sleep(time_to_wait)'''

    #task()
    # 设置任务在午夜零点执行
    schedule.every().day.at("18:30").do(task)
    print("Scheduled jobs:", schedule.get_jobs())


    # 进入一个循环，每天执行一次任务
    while True:
        schedule.run_pending()
        time.sleep(60)  # 每分钟检查一次任务
    # 计算循环的总运行时间
