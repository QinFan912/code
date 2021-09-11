import pathlib
import os

# os.path.abspath(__file__)  获取当前执行脚本的完成路径，也就是说只有当前脚本执行时，该语句才会执行
# pathlib.Path.parent  获取当前path路径的上级路径
# basedir = "E:/Pycharm/similar/pretrain_model"
# print(basedir2)
# print(os.path.join(basedir, '/bert_pretrain/pretrain_model/two_bytes-500/bert_config.json'))

class Config:

    def __init__(self):
        # bert config 文件
        self.bert_config_file = "E:/Pycharm/similar/pretrain_model/bert-pretrain/pretrain_model/two_bytes-500" \
                                "/bert_config.json "
        # bert vocab 文件
        self.vocab_file = "E:/Pycharm/similar/pretrain_model/bert-pretrain/pretrain_model/two_bytes-500/vocab.txt"
        # bert 模型使用的数据路径
        self.data_dir = "E:/Pycharm/similar/pretrain_model/bert_mine/data"
        # 模型输出路径
        self.output_dir = 'E:/Pycharm/similar/pretrain_model/bert-pretrain/bert_sim/results'
        # self.predict_file = basedir + '/bert_mine/dev.txt'
        # self.test_file = basedir + '/bert_mine/test.txt'
        # 预训练模型地址
        self.init_checkpoint = "E:/Pycharm/similar/pretrain_model/bert-pretrain/pretrain_model/two_bytes-500" \
                               "/bert_model.ckpt"

        self.train_checkpoint = 'E:/Pycharm/similar/pretrain_model/bert-pretrain/bert_sim/results'

        self.do_lower_case = True
        self.verbose_logging = False
        self.master = None
        self.version_2_with_negative = False
        self.null_score_diff_threshold = 0.0
        self.use_tpu = False
        self.tpu_name = None
        self.tpu_zone = None
        self.gcp_project = None
        self.num_tpu_cores = 8
        self.task_name = 'sim'
        self.gpu_memory_fraction = 0.8

        self.max_seq_length = 128
        self.doc_stride = 128
        self.max_query_length = 64

        self.do_train = True
        self.do_predict = True
        self.batch_size = 32
        self.predict_batch_size = 8
        self.learning_rate = 5e-5
        self.num_train_epochs = 3.0
        self.warmup_proportion = 0.1
        self.save_checkpoints_steps = 1000
        self.iterations_per_loop = 1000
        self.n_best_size = 20
        self.max_answer_length = 30
        self.eval_batch_size = 16
        # self.do_eval = False
