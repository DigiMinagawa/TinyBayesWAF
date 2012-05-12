#!/bin/sh -
# -*- coding: utf-8 -*-
import math
import sys

__doc__ = ''' NaiveBayesClass.
このクラスではNaiveBayesの処理を行う
gihyo.jp
http://gihyo.jp/dev/serial/01/machine-learning/0003
'''

#yahoo!形態素解析
import morphological
import pickle


"""
getwords
文章の分解をするメソッド
"""
def getwords(doc):
    words = [s.lower() for s in morphological.split(doc)]
    #print s.lower()
    return tuple(w for w in words)

class NaiveBayes:
    """
    __init__
    コンストラクタ
    """
    def __init__(self):
        self.vocabularies = set() # 単語の集合
        self.wordcount = {}       # {category : { words : n, ...}}
        self.catcount = {}        # {category : n}
        

    """
    wordcountup
    wordcountカテゴリ中に単語が何回出てきたか判断
    trainメソッドから呼ばれる
    """
    def wordcountup(self, word, cat):
        self.wordcount.setdefault(cat, {})
        self.wordcount[cat].setdefault(word, 0)
        self.wordcount[cat][word] += 1
        self.vocabularies.add(word)

    """
    catcountup
    カテゴリの単語数
    trainメソッドから呼ばれる
    """
    def catcountup(self, cat):
        self.catcount.setdefault(cat, 0)
        self.catcount[cat] += 1

    """
    train
    トレーニングメソッド
    ドキュメントとカテゴリを引数とする
    """
    def train(self, doc, cat):
        word = getwords(doc);
        for w in word:
            self.wordcountup(w, cat)
        self.catcountup(cat)
    

    ##################
    #推定フェーズ
    ##################
    """
    classifier
    確率値対数の比率
    """
    def classifier(self, doc):
        best = None # 最適なカテゴリ
        max = -sys.maxint
        word = getwords(doc)
        
        # カテゴリ毎に確率の対数を求める
        for cat in self.catcount.keys():
            prob = self.score(word, cat)
            if prob > max:
                max = prob
                best = cat
        return best

    """
    score
    確率値対数の算出
    classifierから呼ばれる
    """
    def score(self, word, cat):
        score = math.log(self.priorprob(cat))
        for w in word:
            score += math.log(self.wordprob(w, cat))
        return score

    """
    priorprob
    catの生起確率P(cat)を求める
    """
    def priorprob(self, cat):
        return float(self.catcount[cat]) / sum(self.catcount.values())

    """
    incategory
    あるカテゴリの中に単語が登場した回数を返す
    wordprobメソッドから呼ばれる
    """
    def incategory(self, word, cat):
        #あるカテゴリの中に単語が登場した回数を返す
        if word in self.wordcount[cat]:
            return float(self.wordcount[cat][word])
        return 0.0

    """
    wordprob
    P(word|cat)が生起する確率を求める
    """
    def wordprob(self, word, cat):
        # P(word|cat)が生起する確率を求める
        prob = \
            (self.incategory(word, cat) + 1.0) / \
                  (sum(self.wordcount[cat].values()) + \
                   len(self.vocabularies) * 1.0)
        return prob

def naive_test():
    
    nb = NaiveBayes()
        
    nb.train(u'''Python（パイソン）は、オランダ人のグイド・ヴァンロッサムが作ったオープンソースのプログラミング言語。
    オブジェクト指向スクリプト言語の一種であり、Perlとともに欧米で広く普及している。イギリスのテレビ局 BBC が製作したコメディ番組『空飛ぶモンティパイソン』にちなんで名付けられた。
    Pythonは英語で爬虫類のニシキヘビの意味で、Python言語のマスコットやアイコンとして使われることがある。Pythonは汎用の高水準言語である。プログラマの生産性とコードの信頼性を重視して設計されており、核となるシンタックスおよびセマンティクスは必要最小限に抑えられている反面、利便性の高い大規模な標準ライブラリを備えている。
    Unicodeによる文字列操作をサポートしており、日本語処理も標準で可能である。 多くのプラットフォームをサポートしており（動作するプラットフォーム）、また、豊富なドキュメント、豊富なライブラリがあることから、産業界でも利用が増えつつある。''', 'Python')

    nb.train(u'''Ruby（ルビー）は、まつもとゆきひろ（通称Matz）により開発されたオブジェクト指向スクリプト言語であり、従来Perlなどのスクリプト言語が用いられてきた領域でのオブジェクト指向プログラミングを実現する。Rubyは当初1993年2月24日に生まれ、1995年12月にfj上で発表された。名称のRubyは、プログラミング言語Perlが6月の誕生石であるPearl（真珠）と同じ発音をすることから、まつもとの同僚の誕生石（7月）のルビーを取って名付けられた。''', 'Ruby')

    nb.train(u'''豊富な機械学習（きかいがくしゅう、Machine learning）とは、人工知能における研究課題の一つで、人間が自然に行っている学習能力と同様の機能をコンピュータで実現させるための技術・手法のことである。 ある程度の数のサンプルデータ集合を対象に解析を行い、そのデータから有用な規則、ルール、知識表現、判断基準などを抽出する。 データ集合を解析するため、統計学との関連も非常に深い。機械学習は検索エンジン、医療診断、スパムメールの検出、金融市場の予測、DNA配列の分類、音声認識や文字認識などのパターン認識、ゲーム戦略、ロボット、など幅広い分野で用いられている。応用分野の特性に応じて学習手法も適切に選択する必要があり、様々な手法が提案されている。それらの手法は、Machine Learning や IEEE Transactions on Pattern Analysis and Machine Intelligence などの学術雑誌などで発表されることが多い。''', u'機械学習')
        
    
    #Python
    words = u'ヴァンロッサム氏によって開発されました.'
    print u'%s => 推定カテゴリ: %s' % (words ,nb.classifier(words))

    words = u'豊富なドキュメントや豊富なライブラリがあります.'
    print u'%s => 推定カテゴリ: %s' % (words ,nb.classifier(words))

    #Ruby
    words = u'純粋なオブジェクト指向言語です.'
    print u'%s => 推定カテゴリ: %s' % (words ,nb.classifier(words))

    words = u'Rubyはまつもとゆきひろ氏(通称Matz)により開発されました.'
    print u'%s => 推定カテゴリ: %s' % (words ,nb.classifier(words))

    #機械学習
    words = u'「機械学習 はじめよう」が始まりました.'
    print u'%s => 推定カテゴリ: %s' % (words ,nb.classifier(words))

    words = u'検索エンジンや画像認識に利用されています.'
    print u'%s => 推定カテゴリ: %s' % (words , nb.classifier(words))

##################
#TEST
##################
if __name__ == "__main__":
    naive_test()
