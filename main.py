from nfstream import NFStreamer
from datetime import datetime


class DataAnalyzer:
    def __init__(self, file_name):
        self.file_name = file_name
        self.streamer = NFStreamer(source = file_name)
        self.streamer = self.streamer.to_pandas(columns_to_anonymize=[])
        self.start = datetime.fromtimestamp(self.streamer['bidirectional_first_seen_ms'].min()/1000.0).strftime('%Y-%m-%d %H:%M:%S')
        self.end = datetime.fromtimestamp(self.streamer['bidirectional_last_seen_ms'].max()/1000.0).strftime('%Y-%m-%d %H:%M:%S')
        self.columns=['src_ip', 'dst_ip', 'bidirectional_packets', 'bidirectional_bytes', 'application_name', 'application_category_name']
        self.unique_columns =  ['src_ip','dst_ip', 'application_name']

        for c in self.streamer.columns:
          if c not in self.columns:
            del self.streamer[c]

    def capturing_time(self):
      return self.start, self.end
    
    def get_data(self):
      return self.streamer.to_markdown()

    def get_unique_data(self, column):
      res_df = self.streamer.copy(deep=True)
      res_df = res_df[self.unique_columns]
      res_df.drop_duplicates(subset=column, inplace=True)
      return res_df.to_markdown()
     
    def vpn_used(self):
      if 'VPN' in self.streamer['application_category_name'].unique():
        return 'VPN используется'
      else:
        return 'VPN не используется'

    def helpful_information(self):
      res_df = self.streamer.copy(deep=True)
      res_df = res_df[['application_name', 'application_category_name', 'bidirectional_bytes']]
      res_df = res_df.groupby(['application_name', 'application_category_name'], as_index=False)[['bidirectional_bytes']].sum().sort_values(['bidirectional_bytes'], ascending=False)
      return res_df.to_markdown()

    
    def get_report(self):
        with open('README.md', 'w',  encoding='utf-8') as f:
            f.write("#    Отчет по лабораторной работе 3.2\n### Выполнили:\n #### Губенко Иван\n #### Пархоменко Александр\n #### Чуйко Михаил\n\n")
            f.write(f"####    Файл захвата: [{self.file_name}]({self.file_name})\n\n")
            f.write(f"#### 1    Наличие VPN: {self.vpn_used()}\n\n")
            f.write(f"#### 2.1    Вывод информации о данных:['src_ip','dst_ip','bidirectional_packets','bidirectional_bytes','application_name','application_category_name']:\n {self.get_data()}\n\n")
            f.write(f"#### 2.2    Уникальные значения ['src_ip']:\n {self.get_unique_data('src_ip')}\n\n")
            f.write(f"#### 3   Время захвата: {self.capturing_time()}\n\n")
            f.write(f"#### 4   Полeзная информация:\n {self.helpful_information()}\n\n")








if __name__ == '__main__':
    streamer = DataAnalyzer('data/all_3.pcapng')
    streamer.get_report()