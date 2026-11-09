/**
 * SentinelAI: Phishing & Scam Link Shield
 * Pre-Trained Machine Learning Model (Random Forest Ensemble)
 *
 * Generated via m2cgen transpiler from scikit-learn RandomForestClassifier.
 * Pure mathematical inference with ZERO external dependencies.
 *
 * Evaluation Metrics on Unseen Held-Out Domains:
 *   - Accuracy:            97.45%
 *   - Precision:           99.72%
 *   - Recall:              95.96%
 *   - F1-Score:            97.80%
 *   - ROC-AUC:             0.9995
 *   - False Positive Rate: 0.39%
 *   - False Negative Rate: 4.04%
 *
 * Input Feature Vector (14 dimensions):
 *   [0]  url_length               (integer)
 *   [1]  domain_length            (integer)
 *   [2]  num_dots                 (integer)
 *   [3]  has_ip                   (0 | 1)
 *   [4]  has_at_symbol            (0 | 1)
 *   [5]  num_hyphens              (integer)
 *   [6]  num_subdomains           (integer)
 *   [7]  is_https                 (0 | 1)
 *   [8]  has_double_slash_in_path (0 | 1)
 *   [9]  num_suspicious_keywords  (integer)
 *   [10] has_suspicious_tld       (0 | 1)
 *   [11] num_query_params         (integer)
 *   [12] special_char_count       (integer)
 *   [13] domain_entropy           (float)
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SentinelModel = factory();
    // Expose root predictPhishingScore for service worker compatibility
    root.predictPhishingScore = root.SentinelModel.predictPhishingScore;
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const FEATURE_NAMES = [
  "url_length",
  "domain_length",
  "num_dots",
  "has_ip",
  "has_at_symbol",
  "num_hyphens",
  "num_subdomains",
  "is_https",
  "has_double_slash_in_path",
  "num_suspicious_keywords",
  "has_suspicious_tld",
  "num_query_params",
  "special_char_count",
  "domain_entropy"
];
  const MODEL_VERSION = "rf-20261109-063632";

  function score(input) {
    var var0;
    if (input[7] <= 0.5) {
        if (input[9] <= 0.5) {
            if (input[1] <= 10.5) {
                if (input[0] <= 23.5) {
                    var0 = [1.0, 0.0];
                } else {
                    if (input[1] <= 8.5) {
                        if (input[11] <= 0.5) {
                            var0 = [0.6666666666666666, 0.3333333333333333];
                        } else {
                            var0 = [0.3333333333333333, 0.6666666666666666];
                        }
                    } else {
                        if (input[11] <= 0.5) {
                            if (input[2] <= 1.5) {
                                var0 = [0.125, 0.875];
                            } else {
                                var0 = [0.4, 0.6];
                            }
                        } else {
                            var0 = [0.5714285714285714, 0.42857142857142855];
                        }
                    }
                }
            } else {
                if (input[2] <= 2.5) {
                    if (input[1] <= 22.5) {
                        if (input[12] <= 0.5) {
                            if (input[2] <= 1.5) {
                                var0 = [0.4536082474226804, 0.5463917525773195];
                            } else {
                                var0 = [0.7966101694915254, 0.2033898305084746];
                            }
                        } else {
                            if (input[13] <= 3.6325000524520874) {
                                var0 = [0.32142857142857145, 0.6785714285714286];
                            } else {
                                var0 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[10] <= 0.5) {
                            if (input[13] <= 3.799499988555908) {
                                var0 = [0.32142857142857145, 0.6785714285714286];
                            } else {
                                var0 = [0.013888888888888888, 0.9861111111111112];
                            }
                        } else {
                            var0 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[6] <= 1.0) {
                        var0 = [0.0, 1.0];
                    } else {
                        if (input[5] <= 0.5) {
                            if (input[2] <= 3.5) {
                                var0 = [0.0410958904109589, 0.958904109589041];
                            } else {
                                var0 = [0.0, 1.0];
                            }
                        } else {
                            var0 = [0.0, 1.0];
                        }
                    }
                }
            }
        } else {
            if (input[6] <= 0.5) {
                if (input[10] <= 0.5) {
                    if (input[1] <= 7.5) {
                        var0 = [1.0, 0.0];
                    } else {
                        if (input[3] <= 0.5) {
                            if (input[13] <= 3.20550000667572) {
                                var0 = [0.06666666666666667, 0.9333333333333333];
                            } else {
                                var0 = [0.2777777777777778, 0.7222222222222222];
                            }
                        } else {
                            var0 = [0.0, 1.0];
                        }
                    }
                } else {
                    var0 = [0.0, 1.0];
                }
            } else {
                if (input[0] <= 38.0) {
                    var0 = [1.0, 0.0];
                } else {
                    var0 = [0.0, 1.0];
                }
            }
        }
    } else {
        var0 = [1.0, 0.0];
    }
    var var1;
    if (input[11] <= 1.5) {
        if (input[9] <= 0.5) {
            if (input[3] <= 0.5) {
                if (input[12] <= 2.5) {
                    if (input[5] <= 1.5) {
                        if (input[0] <= 62.5) {
                            if (input[6] <= 2.5) {
                                var1 = [0.9696969696969697, 0.030303030303030304];
                            } else {
                                var1 = [0.4375, 0.5625];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var1 = [0.0, 1.0];
                            } else {
                                var1 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[2] <= 2.5) {
                            var1 = [0.2571428571428571, 0.7428571428571429];
                        } else {
                            var1 = [0.0, 1.0];
                        }
                    }
                } else {
                    var1 = [0.0, 1.0];
                }
            } else {
                var1 = [0.0, 1.0];
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[0] <= 33.0) {
                    if (input[0] <= 28.5) {
                        var1 = [1.0, 0.0];
                    } else {
                        if (input[13] <= 3.0635000467300415) {
                            var1 = [0.0, 1.0];
                        } else {
                            var1 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[1] <= 11.5) {
                        if (input[13] <= 2.8660000562667847) {
                            var1 = [0.6666666666666666, 0.3333333333333333];
                        } else {
                            var1 = [0.0, 1.0];
                        }
                    } else {
                        if (input[2] <= 2.5) {
                            if (input[0] <= 38.0) {
                                var1 = [0.5714285714285714, 0.42857142857142855];
                            } else {
                                var1 = [0.004464285714285714, 0.9955357142857143];
                            }
                        } else {
                            var1 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var1 = [1.0, 0.0];
            }
        }
    } else {
        var1 = [0.0, 1.0];
    }
    var var2;
    if (input[12] <= 2.5) {
        if (input[2] <= 2.5) {
            if (input[12] <= 0.5) {
                if (input[5] <= 1.5) {
                    if (input[0] <= 61.5) {
                        if (input[10] <= 0.5) {
                            if (input[1] <= 23.5) {
                                var2 = [0.9798799858806918, 0.020120014119308152];
                            } else {
                                var2 = [0.8658536585365854, 0.13414634146341464];
                            }
                        } else {
                            var2 = [0.0, 1.0];
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            if (input[2] <= 1.5) {
                                var2 = [0.0, 1.0];
                            } else {
                                var2 = [0.058823529411764705, 0.9411764705882353];
                            }
                        } else {
                            var2 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[10] <= 0.5) {
                        if (input[5] <= 2.5) {
                            if (input[9] <= 0.5) {
                                var2 = [0.23529411764705882, 0.7647058823529411];
                            } else {
                                var2 = [0.0, 1.0];
                            }
                        } else {
                            if (input[1] <= 25.5) {
                                var2 = [0.0, 1.0];
                            } else {
                                var2 = [0.14285714285714285, 0.8571428571428571];
                            }
                        }
                    } else {
                        var2 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[9] <= 0.5) {
                    if (input[6] <= 0.5) {
                        if (input[12] <= 1.5) {
                            var2 = [0.0, 1.0];
                        } else {
                            if (input[7] <= 0.5) {
                                var2 = [0.5555555555555556, 0.4444444444444444];
                            } else {
                                var2 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[0] <= 60.0) {
                            if (input[13] <= 3.6190000772476196) {
                                var2 = [1.0, 0.0];
                            } else {
                                var2 = [0.5862068965517241, 0.41379310344827586];
                            }
                        } else {
                            if (input[0] <= 63.0) {
                                var2 = [0.3333333333333333, 0.6666666666666666];
                            } else {
                                var2 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    var2 = [0.0, 1.0];
                }
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[0] <= 25.5) {
                    var2 = [1.0, 0.0];
                } else {
                    if (input[9] <= 0.5) {
                        if (input[5] <= 0.5) {
                            if (input[3] <= 0.5) {
                                var2 = [0.05263157894736842, 0.9473684210526315];
                            } else {
                                var2 = [0.0, 1.0];
                            }
                        } else {
                            var2 = [0.0, 1.0];
                        }
                    } else {
                        if (input[6] <= 1.0) {
                            var2 = [0.0, 1.0];
                        } else {
                            if (input[5] <= 0.5) {
                                var2 = [1.0, 0.0];
                            } else {
                                var2 = [0.0, 1.0];
                            }
                        }
                    }
                }
            } else {
                var2 = [1.0, 0.0];
            }
        }
    } else {
        var2 = [0.0, 1.0];
    }
    var var3;
    if (input[2] <= 2.5) {
        if (input[9] <= 0.5) {
            if (input[11] <= 1.5) {
                if (input[10] <= 0.5) {
                    if (input[0] <= 59.5) {
                        if (input[13] <= 3.8585000038146973) {
                            if (input[12] <= 2.5) {
                                var3 = [0.975736568457539, 0.024263431542461005];
                            } else {
                                var3 = [0.0, 1.0];
                            }
                        } else {
                            if (input[2] <= 1.5) {
                                var3 = [1.0, 0.0];
                            } else {
                                var3 = [0.5, 0.5];
                            }
                        }
                    } else {
                        if (input[0] <= 65.5) {
                            if (input[13] <= 3.63700008392334) {
                                var3 = [0.0, 1.0];
                            } else {
                                var3 = [0.4444444444444444, 0.5555555555555556];
                            }
                        } else {
                            var3 = [0.0, 1.0];
                        }
                    }
                } else {
                    var3 = [0.0, 1.0];
                }
            } else {
                var3 = [0.0, 1.0];
            }
        } else {
            if (input[13] <= 2.447000026702881) {
                if (input[0] <= 44.5) {
                    var3 = [1.0, 0.0];
                } else {
                    var3 = [0.0, 1.0];
                }
            } else {
                if (input[0] <= 45.5) {
                    if (input[7] <= 0.5) {
                        if (input[1] <= 13.5) {
                            var3 = [1.0, 0.0];
                        } else {
                            if (input[13] <= 3.349500060081482) {
                                var3 = [0.125, 0.875];
                            } else {
                                var3 = [0.6923076923076923, 0.3076923076923077];
                            }
                        }
                    } else {
                        var3 = [1.0, 0.0];
                    }
                } else {
                    if (input[2] <= 1.5) {
                        if (input[12] <= 0.5) {
                            var3 = [0.03125, 0.96875];
                        } else {
                            var3 = [0.0, 1.0];
                        }
                    } else {
                        if (input[1] <= 26.5) {
                            if (input[7] <= 0.5) {
                                var3 = [0.0, 1.0];
                            } else {
                                var3 = [1.0, 0.0];
                            }
                        } else {
                            var3 = [0.0, 1.0];
                        }
                    }
                }
            }
        }
    } else {
        if (input[6] <= 1.0) {
            var3 = [0.0, 1.0];
        } else {
            if (input[6] <= 2.5) {
                if (input[13] <= 3.7960000038146973) {
                    if (input[13] <= 3.6714999675750732) {
                        if (input[0] <= 43.0) {
                            var3 = [1.0, 0.0];
                        } else {
                            if (input[11] <= 0.5) {
                                var3 = [0.8, 0.2];
                            } else {
                                var3 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[0] <= 42.0) {
                            var3 = [1.0, 0.0];
                        } else {
                            if (input[1] <= 24.5) {
                                var3 = [0.4, 0.6];
                            } else {
                                var3 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[0] <= 41.0) {
                        var3 = [1.0, 0.0];
                    } else {
                        var3 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[7] <= 0.5) {
                    var3 = [0.0, 1.0];
                } else {
                    var3 = [1.0, 0.0];
                }
            }
        }
    }
    var var4;
    if (input[1] <= 11.5) {
        if (input[12] <= 2.5) {
            if (input[12] <= 0.5) {
                if (input[13] <= 2.6929999589920044) {
                    if (input[2] <= 2.5) {
                        if (input[0] <= 39.0) {
                            var4 = [1.0, 0.0];
                        } else {
                            if (input[0] <= 43.5) {
                                var4 = [0.8, 0.2];
                            } else {
                                var4 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var4 = [0.0, 1.0];
                    }
                } else {
                    if (input[0] <= 48.5) {
                        if (input[13] <= 2.934999942779541) {
                            if (input[6] <= 0.5) {
                                var4 = [0.9798387096774194, 0.020161290322580645];
                            } else {
                                var4 = [1.0, 0.0];
                            }
                        } else {
                            if (input[2] <= 1.5) {
                                var4 = [0.9967741935483871, 0.0032258064516129032];
                            } else {
                                var4 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var4 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[12] <= 1.5) {
                    var4 = [0.0, 1.0];
                } else {
                    if (input[6] <= 0.5) {
                        if (input[7] <= 0.5) {
                            if (input[0] <= 39.5) {
                                var4 = [1.0, 0.0];
                            } else {
                                var4 = [0.16666666666666666, 0.8333333333333334];
                            }
                        } else {
                            var4 = [1.0, 0.0];
                        }
                    } else {
                        var4 = [1.0, 0.0];
                    }
                }
            }
        } else {
            var4 = [0.0, 1.0];
        }
    } else {
        if (input[0] <= 40.5) {
            if (input[2] <= 2.5) {
                if (input[7] <= 0.5) {
                    if (input[0] <= 33.5) {
                        if (input[6] <= 0.5) {
                            if (input[1] <= 13.5) {
                                var4 = [0.7272727272727273, 0.2727272727272727];
                            } else {
                                var4 = [0.9629629629629629, 0.037037037037037035];
                            }
                        } else {
                            if (input[13] <= 3.1859999895095825) {
                                var4 = [0.9285714285714286, 0.07142857142857142];
                            } else {
                                var4 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[1] <= 16.5) {
                            if (input[1] <= 15.5) {
                                var4 = [0.5172413793103449, 0.4827586206896552];
                            } else {
                                var4 = [0.8, 0.2];
                            }
                        } else {
                            if (input[5] <= 0.5) {
                                var4 = [0.5769230769230769, 0.4230769230769231];
                            } else {
                                var4 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    var4 = [1.0, 0.0];
                }
            } else {
                if (input[2] <= 4.0) {
                    if (input[13] <= 3.041499972343445) {
                        if (input[3] <= 0.5) {
                            var4 = [1.0, 0.0];
                        } else {
                            var4 = [0.0, 1.0];
                        }
                    } else {
                        if (input[1] <= 12.5) {
                            var4 = [0.0, 1.0];
                        } else {
                            var4 = [1.0, 0.0];
                        }
                    }
                } else {
                    var4 = [1.0, 0.0];
                }
            }
        } else {
            if (input[3] <= 0.5) {
                if (input[10] <= 0.5) {
                    if (input[12] <= 2.5) {
                        if (input[7] <= 0.5) {
                            if (input[6] <= 1.5) {
                                var4 = [0.13966480446927373, 0.8603351955307262];
                            } else {
                                var4 = [0.0, 1.0];
                            }
                        } else {
                            var4 = [1.0, 0.0];
                        }
                    } else {
                        var4 = [0.0, 1.0];
                    }
                } else {
                    var4 = [0.0, 1.0];
                }
            } else {
                var4 = [0.0, 1.0];
            }
        }
    }
    var var5;
    if (input[7] <= 0.5) {
        if (input[1] <= 11.5) {
            if (input[12] <= 0.5) {
                if (input[2] <= 2.5) {
                    if (input[13] <= 2.6134999990463257) {
                        var5 = [1.0, 0.0];
                    } else {
                        if (input[6] <= 0.5) {
                            if (input[13] <= 3.021999955177307) {
                                var5 = [0.5652173913043478, 0.43478260869565216];
                            } else {
                                var5 = [0.8333333333333334, 0.16666666666666666];
                            }
                        } else {
                            var5 = [1.0, 0.0];
                        }
                    }
                } else {
                    var5 = [0.0, 1.0];
                }
            } else {
                if (input[9] <= 0.5) {
                    if (input[12] <= 1.5) {
                        var5 = [0.0, 1.0];
                    } else {
                        if (input[13] <= 2.7410000562667847) {
                            var5 = [1.0, 0.0];
                        } else {
                            if (input[1] <= 9.5) {
                                var5 = [0.6666666666666666, 0.3333333333333333];
                            } else {
                                var5 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    var5 = [0.0, 1.0];
                }
            }
        } else {
            if (input[13] <= 3.0554999113082886) {
                if (input[11] <= 1.5) {
                    if (input[6] <= 0.5) {
                        if (input[9] <= 0.5) {
                            if (input[2] <= 2.0) {
                                var5 = [0.21052631578947367, 0.7894736842105263];
                            } else {
                                var5 = [0.0, 1.0];
                            }
                        } else {
                            var5 = [0.0, 1.0];
                        }
                    } else {
                        if (input[0] <= 38.5) {
                            var5 = [1.0, 0.0];
                        } else {
                            var5 = [0.5, 0.5];
                        }
                    }
                } else {
                    var5 = [0.0, 1.0];
                }
            } else {
                if (input[0] <= 36.5) {
                    if (input[0] <= 30.5) {
                        if (input[0] <= 24.5) {
                            if (input[1] <= 12.5) {
                                var5 = [0.8888888888888888, 0.1111111111111111];
                            } else {
                                var5 = [1.0, 0.0];
                            }
                        } else {
                            var5 = [1.0, 0.0];
                        }
                    } else {
                        if (input[5] <= 1.5) {
                            if (input[0] <= 34.5) {
                                var5 = [0.6521739130434783, 0.34782608695652173];
                            } else {
                                var5 = [0.8666666666666667, 0.13333333333333333];
                            }
                        } else {
                            var5 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[13] <= 3.6514999866485596) {
                        if (input[2] <= 1.5) {
                            if (input[0] <= 48.5) {
                                var5 = [0.2, 0.8];
                            } else {
                                var5 = [0.007751937984496124, 0.9922480620155039];
                            }
                        } else {
                            if (input[0] <= 55.0) {
                                var5 = [0.48936170212765956, 0.5106382978723404];
                            } else {
                                var5 = [0.022222222222222223, 0.9777777777777777];
                            }
                        }
                    } else {
                        if (input[2] <= 2.5) {
                            if (input[1] <= 28.5) {
                                var5 = [0.05714285714285714, 0.9428571428571428];
                            } else {
                                var5 = [0.0, 1.0];
                            }
                        } else {
                            var5 = [0.0, 1.0];
                        }
                    }
                }
            }
        }
    } else {
        var5 = [1.0, 0.0];
    }
    var var6;
    if (input[0] <= 40.5) {
        if (input[7] <= 0.5) {
            if (input[9] <= 1.5) {
                if (input[3] <= 0.5) {
                    if (input[1] <= 11.5) {
                        var6 = [0.9367088607594937, 0.06329113924050633];
                    } else {
                        if (input[2] <= 1.5) {
                            var6 = [0.5507246376811594, 0.4492753623188406];
                        } else {
                            if (input[13] <= 3.600499987602234) {
                                var6 = [0.9775280898876404, 0.02247191011235955];
                            } else {
                                var6 = [0.4827586206896552, 0.5172413793103449];
                            }
                        }
                    }
                } else {
                    var6 = [0.0, 1.0];
                }
            } else {
                var6 = [1.0, 0.0];
            }
        } else {
            var6 = [1.0, 0.0];
        }
    } else {
        if (input[2] <= 2.5) {
            if (input[7] <= 0.5) {
                if (input[0] <= 42.5) {
                    if (input[9] <= 0.5) {
                        var6 = [1.0, 0.0];
                    } else {
                        var6 = [0.3333333333333333, 0.6666666666666666];
                    }
                } else {
                    if (input[6] <= 0.5) {
                        if (input[1] <= 20.5) {
                            if (input[1] <= 19.5) {
                                var6 = [0.02631578947368421, 0.9736842105263158];
                            } else {
                                var6 = [0.4, 0.6];
                            }
                        } else {
                            var6 = [0.0, 1.0];
                        }
                    } else {
                        if (input[12] <= 2.5) {
                            if (input[0] <= 59.5) {
                                var6 = [0.43243243243243246, 0.5675675675675675];
                            } else {
                                var6 = [0.0, 1.0];
                            }
                        } else {
                            var6 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var6 = [1.0, 0.0];
            }
        } else {
            if (input[6] <= 1.0) {
                var6 = [0.0, 1.0];
            } else {
                if (input[12] <= 2.5) {
                    if (input[0] <= 68.5) {
                        if (input[0] <= 65.5) {
                            if (input[7] <= 0.5) {
                                var6 = [0.0, 1.0];
                            } else {
                                var6 = [1.0, 0.0];
                            }
                        } else {
                            var6 = [0.6666666666666666, 0.3333333333333333];
                        }
                    } else {
                        var6 = [0.0, 1.0];
                    }
                } else {
                    var6 = [0.0, 1.0];
                }
            }
        }
    }
    var var7;
    if (input[0] <= 40.5) {
        if (input[0] <= 29.5) {
            if (input[7] <= 0.5) {
                if (input[5] <= 0.5) {
                    if (input[13] <= 2.4905000925064087) {
                        if (input[13] <= 2.337499976158142) {
                            var7 = [1.0, 0.0];
                        } else {
                            var7 = [0.0, 1.0];
                        }
                    } else {
                        if (input[0] <= 25.5) {
                            if (input[1] <= 12.5) {
                                var7 = [0.9577464788732394, 0.04225352112676056];
                            } else {
                                var7 = [1.0, 0.0];
                            }
                        } else {
                            if (input[13] <= 3.0514999628067017) {
                                var7 = [0.18181818181818182, 0.8181818181818182];
                            } else {
                                var7 = [0.9333333333333333, 0.06666666666666667];
                            }
                        }
                    }
                } else {
                    var7 = [1.0, 0.0];
                }
            } else {
                var7 = [1.0, 0.0];
            }
        } else {
            if (input[2] <= 2.5) {
                if (input[12] <= 0.5) {
                    if (input[5] <= 2.5) {
                        if (input[6] <= 0.5) {
                            if (input[10] <= 0.5) {
                                var7 = [0.937125748502994, 0.06287425149700598];
                            } else {
                                var7 = [0.0, 1.0];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var7 = [0.7441860465116279, 0.2558139534883721];
                            } else {
                                var7 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var7 = [0.0, 1.0];
                    }
                } else {
                    var7 = [0.7560975609756098, 0.24390243902439024];
                }
            } else {
                if (input[6] <= 1.0) {
                    var7 = [0.0, 1.0];
                } else {
                    var7 = [1.0, 0.0];
                }
            }
        }
    } else {
        if (input[13] <= 3.072000026702881) {
            if (input[3] <= 0.5) {
                if (input[0] <= 57.0) {
                    if (input[11] <= 0.5) {
                        if (input[12] <= 0.5) {
                            if (input[0] <= 50.5) {
                                var7 = [1.0, 0.0];
                            } else {
                                var7 = [0.6666666666666666, 0.3333333333333333];
                            }
                        } else {
                            var7 = [0.0, 1.0];
                        }
                    } else {
                        var7 = [1.0, 0.0];
                    }
                } else {
                    var7 = [0.0, 1.0];
                }
            } else {
                var7 = [0.0, 1.0];
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[0] <= 59.5) {
                    if (input[12] <= 1.5) {
                        if (input[5] <= 0.5) {
                            if (input[13] <= 3.1894999742507935) {
                                var7 = [0.0, 1.0];
                            } else {
                                var7 = [0.15517241379310345, 0.8448275862068966];
                            }
                        } else {
                            var7 = [0.0, 1.0];
                        }
                    } else {
                        if (input[13] <= 3.2725000381469727) {
                            var7 = [1.0, 0.0];
                        } else {
                            if (input[2] <= 1.5) {
                                var7 = [0.35714285714285715, 0.6428571428571429];
                            } else {
                                var7 = [0.8, 0.2];
                            }
                        }
                    }
                } else {
                    if (input[2] <= 1.5) {
                        var7 = [0.0, 1.0];
                    } else {
                        if (input[1] <= 26.5) {
                            if (input[0] <= 62.5) {
                                var7 = [0.2, 0.8];
                            } else {
                                var7 = [0.0, 1.0];
                            }
                        } else {
                            var7 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var7 = [1.0, 0.0];
            }
        }
    }
    var var8;
    if (input[0] <= 41.5) {
        if (input[3] <= 0.5) {
            if (input[5] <= 1.5) {
                if (input[12] <= 0.5) {
                    if (input[9] <= 0.5) {
                        if (input[0] <= 36.5) {
                            if (input[6] <= 0.5) {
                                var8 = [0.9834494773519163, 0.016550522648083623];
                            } else {
                                var8 = [0.9983457402812241, 0.0016542597187758478];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var8 = [0.4444444444444444, 0.5555555555555556];
                            } else {
                                var8 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[0] <= 38.5) {
                            if (input[1] <= 13.5) {
                                var8 = [1.0, 0.0];
                            } else {
                                var8 = [0.9727272727272728, 0.02727272727272727];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var8 = [0.6, 0.4];
                            } else {
                                var8 = [0.8823529411764706, 0.11764705882352941];
                            }
                        }
                    }
                } else {
                    if (input[7] <= 0.5) {
                        if (input[6] <= 0.5) {
                            var8 = [0.4, 0.6];
                        } else {
                            var8 = [0.3333333333333333, 0.6666666666666666];
                        }
                    } else {
                        var8 = [1.0, 0.0];
                    }
                }
            } else {
                if (input[0] <= 38.5) {
                    if (input[6] <= 0.5) {
                        var8 = [0.3333333333333333, 0.6666666666666666];
                    } else {
                        var8 = [0.0, 1.0];
                    }
                } else {
                    var8 = [1.0, 0.0];
                }
            }
        } else {
            var8 = [0.0, 1.0];
        }
    } else {
        if (input[0] <= 56.5) {
            if (input[7] <= 0.5) {
                if (input[2] <= 2.5) {
                    if (input[11] <= 0.5) {
                        if (input[1] <= 27.5) {
                            if (input[0] <= 43.5) {
                                var8 = [0.3333333333333333, 0.6666666666666666];
                            } else {
                                var8 = [0.0, 1.0];
                            }
                        } else {
                            var8 = [0.25, 0.75];
                        }
                    } else {
                        var8 = [1.0, 0.0];
                    }
                } else {
                    var8 = [0.0, 1.0];
                }
            } else {
                var8 = [1.0, 0.0];
            }
        } else {
            if (input[0] <= 60.5) {
                if (input[3] <= 0.5) {
                    if (input[7] <= 0.5) {
                        if (input[9] <= 0.5) {
                            if (input[6] <= 0.5) {
                                var8 = [0.14285714285714285, 0.8571428571428571];
                            } else {
                                var8 = [0.0, 1.0];
                            }
                        } else {
                            var8 = [0.0, 1.0];
                        }
                    } else {
                        var8 = [1.0, 0.0];
                    }
                } else {
                    var8 = [0.0, 1.0];
                }
            } else {
                if (input[5] <= 0.5) {
                    if (input[6] <= 0.5) {
                        var8 = [0.0, 1.0];
                    } else {
                        if (input[0] <= 62.5) {
                            var8 = [0.2857142857142857, 0.7142857142857143];
                        } else {
                            var8 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[9] <= 0.5) {
                        if (input[5] <= 1.5) {
                            if (input[2] <= 1.5) {
                                var8 = [0.0, 1.0];
                            } else {
                                var8 = [0.25, 0.75];
                            }
                        } else {
                            var8 = [0.0, 1.0];
                        }
                    } else {
                        var8 = [0.0, 1.0];
                    }
                }
            }
        }
    }
    var var9;
    if (input[3] <= 0.5) {
        if (input[0] <= 57.5) {
            if (input[0] <= 47.5) {
                if (input[2] <= 3.5) {
                    if (input[1] <= 24.5) {
                        if (input[10] <= 0.5) {
                            if (input[13] <= 3.8450000286102295) {
                                var9 = [0.9777049180327869, 0.022295081967213116];
                            } else {
                                var9 = [0.6538461538461539, 0.34615384615384615];
                            }
                        } else {
                            var9 = [0.0, 1.0];
                        }
                    } else {
                        if (input[5] <= 2.5) {
                            if (input[6] <= 1.5) {
                                var9 = [0.8245614035087719, 0.17543859649122806];
                            } else {
                                var9 = [1.0, 0.0];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var9 = [0.0, 1.0];
                            } else {
                                var9 = [1.0, 0.0];
                            }
                        }
                    }
                } else {
                    if (input[13] <= 3.6399999856948853) {
                        var9 = [1.0, 0.0];
                    } else {
                        var9 = [0.5, 0.5];
                    }
                }
            } else {
                if (input[11] <= 0.5) {
                    if (input[7] <= 0.5) {
                        var9 = [0.0, 1.0];
                    } else {
                        var9 = [1.0, 0.0];
                    }
                } else {
                    var9 = [1.0, 0.0];
                }
            }
        } else {
            if (input[10] <= 0.5) {
                if (input[1] <= 31.5) {
                    if (input[0] <= 61.5) {
                        if (input[12] <= 1.5) {
                            if (input[1] <= 20.5) {
                                var9 = [0.0, 1.0];
                            } else {
                                var9 = [0.4444444444444444, 0.5555555555555556];
                            }
                        } else {
                            var9 = [1.0, 0.0];
                        }
                    } else {
                        if (input[2] <= 3.5) {
                            if (input[0] <= 65.5) {
                                var9 = [0.1, 0.9];
                            } else {
                                var9 = [0.0, 1.0];
                            }
                        } else {
                            var9 = [0.8, 0.2];
                        }
                    }
                } else {
                    var9 = [0.0, 1.0];
                }
            } else {
                var9 = [0.0, 1.0];
            }
        }
    } else {
        var9 = [0.0, 1.0];
    }
    var var10;
    if (input[3] <= 0.5) {
        if (input[1] <= 27.5) {
            if (input[11] <= 1.5) {
                if (input[7] <= 0.5) {
                    if (input[13] <= 3.5225000381469727) {
                        if (input[13] <= 2.728500008583069) {
                            if (input[13] <= 2.5535000562667847) {
                                var10 = [1.0, 0.0];
                            } else {
                                var10 = [0.85, 0.15];
                            }
                        } else {
                            if (input[0] <= 36.5) {
                                var10 = [0.8987341772151899, 0.10126582278481013];
                            } else {
                                var10 = [0.17857142857142858, 0.8214285714285714];
                            }
                        }
                    } else {
                        if (input[2] <= 1.5) {
                            if (input[13] <= 3.5464999675750732) {
                                var10 = [0.0, 1.0];
                            } else {
                                var10 = [0.3783783783783784, 0.6216216216216216];
                            }
                        } else {
                            if (input[2] <= 3.5) {
                                var10 = [0.1875, 0.8125];
                            } else {
                                var10 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    var10 = [1.0, 0.0];
                }
            } else {
                var10 = [0.0, 1.0];
            }
        } else {
            if (input[0] <= 41.5) {
                if (input[13] <= 3.8289999961853027) {
                    var10 = [1.0, 0.0];
                } else {
                    if (input[0] <= 39.0) {
                        var10 = [1.0, 0.0];
                    } else {
                        var10 = [0.5, 0.5];
                    }
                }
            } else {
                if (input[13] <= 3.937000036239624) {
                    var10 = [0.0, 1.0];
                } else {
                    if (input[13] <= 3.944499969482422) {
                        var10 = [0.75, 0.25];
                    } else {
                        if (input[12] <= 0.5) {
                            if (input[13] <= 4.080499887466431) {
                                var10 = [0.16666666666666666, 0.8333333333333334];
                            } else {
                                var10 = [0.0, 1.0];
                            }
                        } else {
                            var10 = [0.0, 1.0];
                        }
                    }
                }
            }
        }
    } else {
        var10 = [0.0, 1.0];
    }
    var var11;
    if (input[13] <= 2.909000039100647) {
        if (input[2] <= 2.5) {
            if (input[1] <= 22.0) {
                if (input[13] <= 2.8739999532699585) {
                    if (input[13] <= 2.5535000562667847) {
                        var11 = [1.0, 0.0];
                    } else {
                        if (input[1] <= 7.5) {
                            var11 = [1.0, 0.0];
                        } else {
                            if (input[2] <= 1.5) {
                                var11 = [0.9468599033816425, 0.05314009661835749];
                            } else {
                                var11 = [1.0, 0.0];
                            }
                        }
                    }
                } else {
                    var11 = [0.5, 0.5];
                }
            } else {
                var11 = [0.0, 1.0];
            }
        } else {
            if (input[6] <= 1.0) {
                var11 = [0.0, 1.0];
            } else {
                var11 = [1.0, 0.0];
            }
        }
    } else {
        if (input[1] <= 27.5) {
            if (input[12] <= 2.5) {
                if (input[2] <= 2.5) {
                    if (input[7] <= 0.5) {
                        if (input[0] <= 33.5) {
                            if (input[9] <= 0.5) {
                                var11 = [0.906832298136646, 0.09316770186335403];
                            } else {
                                var11 = [0.75, 0.25];
                            }
                        } else {
                            if (input[0] <= 61.5) {
                                var11 = [0.2265193370165746, 0.7734806629834254];
                            } else {
                                var11 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var11 = [1.0, 0.0];
                    }
                } else {
                    if (input[1] <= 15.5) {
                        if (input[7] <= 0.5) {
                            var11 = [0.0, 1.0];
                        } else {
                            var11 = [1.0, 0.0];
                        }
                    } else {
                        if (input[6] <= 2.5) {
                            if (input[0] <= 77.0) {
                                var11 = [0.9690721649484536, 0.030927835051546393];
                            } else {
                                var11 = [0.0, 1.0];
                            }
                        } else {
                            if (input[6] <= 3.5) {
                                var11 = [0.13333333333333333, 0.8666666666666667];
                            } else {
                                var11 = [1.0, 0.0];
                            }
                        }
                    }
                }
            } else {
                var11 = [0.0, 1.0];
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[12] <= 0.5) {
                    if (input[6] <= 1.5) {
                        if (input[2] <= 1.5) {
                            var11 = [0.0, 1.0];
                        } else {
                            var11 = [0.11538461538461539, 0.8846153846153846];
                        }
                    } else {
                        var11 = [0.0, 1.0];
                    }
                } else {
                    var11 = [0.0, 1.0];
                }
            } else {
                var11 = [1.0, 0.0];
            }
        }
    }
    var var12;
    if (input[7] <= 0.5) {
        if (input[2] <= 2.5) {
            if (input[1] <= 22.5) {
                if (input[12] <= 0.5) {
                    if (input[2] <= 1.5) {
                        if (input[10] <= 0.5) {
                            if (input[13] <= 2.881500005722046) {
                                var12 = [0.9148936170212766, 0.0851063829787234];
                            } else {
                                var12 = [0.5, 0.5];
                            }
                        } else {
                            var12 = [0.0, 1.0];
                        }
                    } else {
                        var12 = [0.8809523809523809, 0.11904761904761904];
                    }
                } else {
                    if (input[1] <= 19.5) {
                        if (input[6] <= 0.5) {
                            if (input[13] <= 3.103500008583069) {
                                var12 = [0.32142857142857145, 0.6785714285714286];
                            } else {
                                var12 = [0.05660377358490566, 0.9433962264150944];
                            }
                        } else {
                            if (input[11] <= 0.5) {
                                var12 = [0.0, 1.0];
                            } else {
                                var12 = [0.7142857142857143, 0.2857142857142857];
                            }
                        }
                    } else {
                        if (input[13] <= 3.436500072479248) {
                            var12 = [0.3333333333333333, 0.6666666666666666];
                        } else {
                            var12 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                if (input[0] <= 44.5) {
                    var12 = [0.5384615384615384, 0.46153846153846156];
                } else {
                    if (input[12] <= 0.5) {
                        if (input[5] <= 0.5) {
                            if (input[1] <= 23.5) {
                                var12 = [0.2857142857142857, 0.7142857142857143];
                            } else {
                                var12 = [0.03571428571428571, 0.9642857142857143];
                            }
                        } else {
                            var12 = [0.0, 1.0];
                        }
                    } else {
                        if (input[10] <= 0.5) {
                            if (input[11] <= 0.5) {
                                var12 = [0.0, 1.0];
                            } else {
                                var12 = [0.027777777777777776, 0.9722222222222222];
                            }
                        } else {
                            var12 = [0.0, 1.0];
                        }
                    }
                }
            }
        } else {
            if (input[4] <= 0.5) {
                if (input[3] <= 0.5) {
                    if (input[11] <= 0.5) {
                        if (input[9] <= 0.5) {
                            if (input[5] <= 0.5) {
                                var12 = [0.10416666666666667, 0.8958333333333334];
                            } else {
                                var12 = [0.0, 1.0];
                            }
                        } else {
                            var12 = [0.0, 1.0];
                        }
                    } else {
                        var12 = [0.0, 1.0];
                    }
                } else {
                    var12 = [0.0, 1.0];
                }
            } else {
                var12 = [0.0, 1.0];
            }
        }
    } else {
        var12 = [1.0, 0.0];
    }
    var var13;
    if (input[7] <= 0.5) {
        if (input[0] <= 28.5) {
            if (input[0] <= 25.5) {
                if (input[6] <= 0.5) {
                    if (input[13] <= 2.6134999990463257) {
                        var13 = [1.0, 0.0];
                    } else {
                        var13 = [0.9333333333333333, 0.06666666666666667];
                    }
                } else {
                    var13 = [1.0, 0.0];
                }
            } else {
                if (input[1] <= 14.5) {
                    if (input[2] <= 2.5) {
                        var13 = [0.6666666666666666, 0.3333333333333333];
                    } else {
                        var13 = [0.0, 1.0];
                    }
                } else {
                    var13 = [1.0, 0.0];
                }
            }
        } else {
            if (input[6] <= 0.5) {
                if (input[2] <= 2.0) {
                    if (input[10] <= 0.5) {
                        if (input[0] <= 36.5) {
                            if (input[5] <= 1.0) {
                                var13 = [0.6538461538461539, 0.34615384615384615];
                            } else {
                                var13 = [0.0, 1.0];
                            }
                        } else {
                            if (input[5] <= 1.5) {
                                var13 = [0.10218978102189781, 0.8978102189781022];
                            } else {
                                var13 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var13 = [0.0, 1.0];
                    }
                } else {
                    var13 = [0.0, 1.0];
                }
            } else {
                if (input[13] <= 3.5479999780654907) {
                    if (input[13] <= 3.455999970436096) {
                        if (input[1] <= 22.0) {
                            if (input[13] <= 3.315500020980835) {
                                var13 = [0.8928571428571429, 0.10714285714285714];
                            } else {
                                var13 = [0.44, 0.56];
                            }
                        } else {
                            var13 = [0.0, 1.0];
                        }
                    } else {
                        var13 = [1.0, 0.0];
                    }
                } else {
                    if (input[0] <= 34.5) {
                        if (input[0] <= 33.5) {
                            var13 = [1.0, 0.0];
                        } else {
                            var13 = [0.5, 0.5];
                        }
                    } else {
                        if (input[12] <= 0.5) {
                            if (input[13] <= 3.9420000314712524) {
                                var13 = [0.14705882352941177, 0.8529411764705882];
                            } else {
                                var13 = [0.0, 1.0];
                            }
                        } else {
                            if (input[5] <= 0.5) {
                                var13 = [0.01694915254237288, 0.9830508474576272];
                            } else {
                                var13 = [0.0, 1.0];
                            }
                        }
                    }
                }
            }
        }
    } else {
        var13 = [1.0, 0.0];
    }
    var var14;
    if (input[2] <= 2.5) {
        if (input[13] <= 3.8945000171661377) {
            if (input[1] <= 27.5) {
                if (input[5] <= 1.5) {
                    if (input[0] <= 59.5) {
                        if (input[7] <= 0.5) {
                            if (input[12] <= 0.5) {
                                var14 = [0.8298611111111112, 0.1701388888888889];
                            } else {
                                var14 = [0.27419354838709675, 0.7258064516129032];
                            }
                        } else {
                            var14 = [1.0, 0.0];
                        }
                    } else {
                        if (input[6] <= 0.5) {
                            var14 = [0.0, 1.0];
                        } else {
                            if (input[0] <= 66.5) {
                                var14 = [0.8, 0.2];
                            } else {
                                var14 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[11] <= 0.5) {
                        var14 = [0.0, 1.0];
                    } else {
                        var14 = [0.5, 0.5];
                    }
                }
            } else {
                if (input[12] <= 1.0) {
                    if (input[2] <= 1.5) {
                        var14 = [0.0, 1.0];
                    } else {
                        if (input[1] <= 32.5) {
                            var14 = [1.0, 0.0];
                        } else {
                            var14 = [0.25, 0.75];
                        }
                    }
                } else {
                    var14 = [0.0, 1.0];
                }
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[13] <= 3.9420000314712524) {
                    if (input[12] <= 0.5) {
                        if (input[5] <= 0.5) {
                            var14 = [0.25, 0.75];
                        } else {
                            var14 = [0.0, 1.0];
                        }
                    } else {
                        var14 = [0.0, 1.0];
                    }
                } else {
                    var14 = [0.0, 1.0];
                }
            } else {
                var14 = [1.0, 0.0];
            }
        }
    } else {
        if (input[13] <= 3.041499972343445) {
            if (input[11] <= 1.5) {
                if (input[6] <= 1.0) {
                    var14 = [0.0, 1.0];
                } else {
                    var14 = [1.0, 0.0];
                }
            } else {
                var14 = [0.0, 1.0];
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[1] <= 21.5) {
                    if (input[13] <= 3.2044999599456787) {
                        var14 = [0.0, 1.0];
                    } else {
                        if (input[13] <= 3.503999948501587) {
                            var14 = [1.0, 0.0];
                        } else {
                            var14 = [0.6666666666666666, 0.3333333333333333];
                        }
                    }
                } else {
                    if (input[2] <= 3.5) {
                        if (input[1] <= 24.5) {
                            if (input[0] <= 41.0) {
                                var14 = [1.0, 0.0];
                            } else {
                                var14 = [0.0, 1.0];
                            }
                        } else {
                            var14 = [0.0, 1.0];
                        }
                    } else {
                        var14 = [0.0, 1.0];
                    }
                }
            } else {
                var14 = [1.0, 0.0];
            }
        }
    }
    var var15;
    if (input[2] <= 2.5) {
        if (input[9] <= 0.5) {
            if (input[10] <= 0.5) {
                if (input[7] <= 0.5) {
                    if (input[5] <= 1.5) {
                        if (input[0] <= 36.5) {
                            if (input[13] <= 2.9394999742507935) {
                                var15 = [0.8148148148148148, 0.18518518518518517];
                            } else {
                                var15 = [0.940677966101695, 0.059322033898305086];
                            }
                        } else {
                            if (input[2] <= 1.5) {
                                var15 = [0.12903225806451613, 0.8709677419354839];
                            } else {
                                var15 = [0.17333333333333334, 0.8266666666666667];
                            }
                        }
                    } else {
                        var15 = [0.0, 1.0];
                    }
                } else {
                    var15 = [1.0, 0.0];
                }
            } else {
                var15 = [0.0, 1.0];
            }
        } else {
            if (input[5] <= 0.5) {
                if (input[2] <= 1.5) {
                    if (input[12] <= 0.5) {
                        if (input[10] <= 0.5) {
                            if (input[13] <= 3.135499954223633) {
                                var15 = [0.9857142857142858, 0.014285714285714285];
                            } else {
                                var15 = [0.8734177215189873, 0.12658227848101267];
                            }
                        } else {
                            var15 = [0.0, 1.0];
                        }
                    } else {
                        var15 = [0.0, 1.0];
                    }
                } else {
                    if (input[0] <= 47.5) {
                        var15 = [1.0, 0.0];
                    } else {
                        if (input[0] <= 55.0) {
                            var15 = [0.5, 0.5];
                        } else {
                            var15 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                if (input[12] <= 0.5) {
                    if (input[0] <= 44.5) {
                        if (input[6] <= 0.5) {
                            if (input[0] <= 33.0) {
                                var15 = [1.0, 0.0];
                            } else {
                                var15 = [0.2, 0.8];
                            }
                        } else {
                            var15 = [1.0, 0.0];
                        }
                    } else {
                        var15 = [0.0, 1.0];
                    }
                } else {
                    var15 = [0.0, 1.0];
                }
            }
        }
    } else {
        if (input[6] <= 1.0) {
            var15 = [0.0, 1.0];
        } else {
            if (input[0] <= 41.5) {
                var15 = [1.0, 0.0];
            } else {
                if (input[6] <= 2.5) {
                    if (input[9] <= 0.5) {
                        if (input[11] <= 0.5) {
                            if (input[7] <= 0.5) {
                                var15 = [0.0, 1.0];
                            } else {
                                var15 = [1.0, 0.0];
                            }
                        } else {
                            var15 = [0.22916666666666666, 0.7708333333333334];
                        }
                    } else {
                        if (input[5] <= 0.5) {
                            var15 = [1.0, 0.0];
                        } else {
                            var15 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[1] <= 23.5) {
                        var15 = [0.3333333333333333, 0.6666666666666666];
                    } else {
                        var15 = [0.0, 1.0];
                    }
                }
            }
        }
    }
    var var16;
    if (input[13] <= 2.9049999713897705) {
        if (input[2] <= 2.5) {
            if (input[10] <= 0.5) {
                if (input[13] <= 2.305000066757202) {
                    if (input[1] <= 7.5) {
                        var16 = [1.0, 0.0];
                    } else {
                        var16 = [0.5714285714285714, 0.42857142857142855];
                    }
                } else {
                    if (input[7] <= 0.5) {
                        if (input[0] <= 52.5) {
                            if (input[0] <= 39.0) {
                                var16 = [0.9772727272727273, 0.022727272727272728];
                            } else {
                                var16 = [0.7777777777777778, 0.2222222222222222];
                            }
                        } else {
                            var16 = [0.0, 1.0];
                        }
                    } else {
                        var16 = [1.0, 0.0];
                    }
                }
            } else {
                var16 = [0.0, 1.0];
            }
        } else {
            if (input[13] <= 2.8604999780654907) {
                if (input[7] <= 0.5) {
                    if (input[4] <= 0.5) {
                        if (input[9] <= 0.5) {
                            var16 = [0.0016406890894175555, 0.9983593109105825];
                        } else {
                            var16 = [0.0, 1.0];
                        }
                    } else {
                        var16 = [0.0, 1.0];
                    }
                } else {
                    var16 = [1.0, 0.0];
                }
            } else {
                if (input[6] <= 1.0) {
                    var16 = [0.0, 1.0];
                } else {
                    var16 = [1.0, 0.0];
                }
            }
        }
    } else {
        if (input[3] <= 0.5) {
            if (input[10] <= 0.5) {
                if (input[12] <= 2.5) {
                    if (input[4] <= 0.5) {
                        if (input[0] <= 55.5) {
                            if (input[2] <= 3.5) {
                                var16 = [0.9544444444444444, 0.04555555555555556];
                            } else {
                                var16 = [0.4166666666666667, 0.5833333333333334];
                            }
                        } else {
                            if (input[11] <= 0.5) {
                                var16 = [0.0738255033557047, 0.9261744966442953];
                            } else {
                                var16 = [0.23728813559322035, 0.7627118644067796];
                            }
                        }
                    } else {
                        var16 = [0.0, 1.0];
                    }
                } else {
                    var16 = [0.0, 1.0];
                }
            } else {
                var16 = [0.0, 1.0];
            }
        } else {
            var16 = [0.0, 1.0];
        }
    }
    var var17;
    if (input[12] <= 2.5) {
        if (input[12] <= 0.5) {
            if (input[1] <= 11.5) {
                if (input[6] <= 0.5) {
                    if (input[3] <= 0.5) {
                        if (input[1] <= 8.5) {
                            var17 = [1.0, 0.0];
                        } else {
                            if (input[9] <= 1.5) {
                                var17 = [0.9876847290640394, 0.012315270935960592];
                            } else {
                                var17 = [0.45454545454545453, 0.5454545454545454];
                            }
                        }
                    } else {
                        var17 = [0.0, 1.0];
                    }
                } else {
                    var17 = [1.0, 0.0];
                }
            } else {
                if (input[9] <= 0.5) {
                    if (input[7] <= 0.5) {
                        if (input[4] <= 0.5) {
                            if (input[3] <= 0.5) {
                                var17 = [0.470404984423676, 0.5295950155763239];
                            } else {
                                var17 = [0.0, 1.0];
                            }
                        } else {
                            var17 = [0.0, 1.0];
                        }
                    } else {
                        var17 = [1.0, 0.0];
                    }
                } else {
                    if (input[3] <= 0.5) {
                        if (input[5] <= 1.5) {
                            if (input[0] <= 56.5) {
                                var17 = [0.9587628865979382, 0.041237113402061855];
                            } else {
                                var17 = [0.0, 1.0];
                            }
                        } else {
                            var17 = [0.0, 1.0];
                        }
                    } else {
                        var17 = [0.0, 1.0];
                    }
                }
            }
        } else {
            if (input[9] <= 0.5) {
                if (input[12] <= 1.5) {
                    var17 = [0.0, 1.0];
                } else {
                    if (input[7] <= 0.5) {
                        if (input[2] <= 2.5) {
                            if (input[0] <= 63.0) {
                                var17 = [0.7037037037037037, 0.2962962962962963];
                            } else {
                                var17 = [0.0, 1.0];
                            }
                        } else {
                            var17 = [0.0, 1.0];
                        }
                    } else {
                        var17 = [1.0, 0.0];
                    }
                }
            } else {
                var17 = [0.0, 1.0];
            }
        }
    } else {
        var17 = [0.0, 1.0];
    }
    var var18;
    if (input[2] <= 2.5) {
        if (input[13] <= 3.791000008583069) {
            if (input[10] <= 0.5) {
                if (input[12] <= 2.5) {
                    if (input[9] <= 2.5) {
                        if (input[1] <= 29.0) {
                            if (input[12] <= 0.5) {
                                var18 = [0.9627477785372522, 0.03725222146274778];
                            } else {
                                var18 = [0.8821428571428571, 0.11785714285714285];
                            }
                        } else {
                            if (input[12] <= 1.0) {
                                var18 = [0.6666666666666666, 0.3333333333333333];
                            } else {
                                var18 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var18 = [0.0, 1.0];
                    }
                } else {
                    var18 = [0.0, 1.0];
                }
            } else {
                var18 = [0.0, 1.0];
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[1] <= 28.5) {
                    if (input[5] <= 0.5) {
                        if (input[13] <= 3.867000102996826) {
                            if (input[0] <= 35.0) {
                                var18 = [0.8, 0.2];
                            } else {
                                var18 = [1.0, 0.0];
                            }
                        } else {
                            if (input[0] <= 45.0) {
                                var18 = [0.8333333333333334, 0.16666666666666666];
                            } else {
                                var18 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var18 = [0.0, 1.0];
                    }
                } else {
                    var18 = [0.0, 1.0];
                }
            } else {
                var18 = [1.0, 0.0];
            }
        }
    } else {
        if (input[1] <= 15.5) {
            if (input[3] <= 0.5) {
                var18 = [1.0, 0.0];
            } else {
                var18 = [0.0, 1.0];
            }
        } else {
            if (input[2] <= 3.5) {
                if (input[5] <= 1.5) {
                    if (input[0] <= 55.0) {
                        if (input[12] <= 1.0) {
                            if (input[1] <= 23.5) {
                                var18 = [1.0, 0.0];
                            } else {
                                var18 = [0.8461538461538461, 0.15384615384615385];
                            }
                        } else {
                            var18 = [1.0, 0.0];
                        }
                    } else {
                        var18 = [0.0, 1.0];
                    }
                } else {
                    var18 = [0.0, 1.0];
                }
            } else {
                if (input[7] <= 0.5) {
                    var18 = [0.0, 1.0];
                } else {
                    var18 = [1.0, 0.0];
                }
            }
        }
    }
    var var19;
    if (input[11] <= 1.5) {
        if (input[2] <= 2.5) {
            if (input[1] <= 24.5) {
                if (input[0] <= 59.5) {
                    if (input[12] <= 0.5) {
                        if (input[0] <= 36.5) {
                            if (input[0] <= 30.5) {
                                var19 = [0.9979306777030522, 0.0020693222969477496];
                            } else {
                                var19 = [0.9599109131403119, 0.0400890868596882];
                            }
                        } else {
                            if (input[10] <= 0.5) {
                                var19 = [0.8671328671328671, 0.13286713286713286];
                            } else {
                                var19 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[6] <= 0.5) {
                                var19 = [0.8333333333333334, 0.16666666666666666];
                            } else {
                                var19 = [0.9439252336448598, 0.056074766355140186];
                            }
                        } else {
                            var19 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[0] <= 61.5) {
                        var19 = [0.375, 0.625];
                    } else {
                        var19 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[12] <= 0.5) {
                    if (input[7] <= 0.5) {
                        if (input[0] <= 35.0) {
                            var19 = [1.0, 0.0];
                        } else {
                            if (input[5] <= 1.5) {
                                var19 = [0.1702127659574468, 0.8297872340425532];
                            } else {
                                var19 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var19 = [1.0, 0.0];
                    }
                } else {
                    if (input[10] <= 0.5) {
                        if (input[11] <= 0.5) {
                            var19 = [0.0, 1.0];
                        } else {
                            if (input[12] <= 2.5) {
                                var19 = [0.15384615384615385, 0.8461538461538461];
                            } else {
                                var19 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var19 = [0.0, 1.0];
                    }
                }
            }
        } else {
            if (input[0] <= 28.5) {
                if (input[7] <= 0.5) {
                    if (input[1] <= 14.5) {
                        if (input[1] <= 13.5) {
                            var19 = [0.3333333333333333, 0.6666666666666666];
                        } else {
                            var19 = [0.0, 1.0];
                        }
                    } else {
                        var19 = [1.0, 0.0];
                    }
                } else {
                    var19 = [1.0, 0.0];
                }
            } else {
                if (input[6] <= 1.0) {
                    var19 = [0.0, 1.0];
                } else {
                    if (input[1] <= 23.5) {
                        if (input[6] <= 2.5) {
                            if (input[12] <= 0.5) {
                                var19 = [1.0, 0.0];
                            } else {
                                var19 = [0.6666666666666666, 0.3333333333333333];
                            }
                        } else {
                            var19 = [0.0, 1.0];
                        }
                    } else {
                        if (input[2] <= 3.5) {
                            if (input[7] <= 0.5) {
                                var19 = [0.012987012987012988, 0.987012987012987];
                            } else {
                                var19 = [1.0, 0.0];
                            }
                        } else {
                            if (input[12] <= 1.5) {
                                var19 = [0.034482758620689655, 0.9655172413793104];
                            } else {
                                var19 = [0.09090909090909091, 0.9090909090909091];
                            }
                        }
                    }
                }
            }
        }
    } else {
        var19 = [0.0, 1.0];
    }
    return mulVectorNumber(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(var0, var1), var2), var3), var4), var5), var6), var7), var8), var9), var10), var11), var12), var13), var14), var15), var16), var17), var18), var19), 0.05);
}
function addVectors(v1, v2) {
    var result = new Array(v1.length);
    for (var i = 0; i < v1.length; i++) {
        result[i] = v1[i] + v2[i];
    }
    return result;
}
function mulVectorNumber(v1, num) {
    var result = new Array(v1.length);
    for (var i = 0; i < v1.length; i++) {
        result[i] = v1[i] * num;
    }
    return result;
}


  /**
   * Sanitizes input into a 14-element numeric array.
   */
  function sanitizeInput(features) {
    if (Array.isArray(features)) {
      const arr = new Array(14).fill(0);
      for (let i = 0; i < Math.min(14, features.length); i++) {
        arr[i] = typeof features[i] === 'number' && !isNaN(features[i]) ? features[i] : 0;
      }
      return arr;
    }
    if (features && typeof features === 'object') {
      return [
        Number(features.url_length ?? features.urlLength ?? 0),
        Number(features.domain_length ?? features.domainLength ?? 0),
        Number(features.num_dots ?? features.numDots ?? 0),
        Number(features.has_ip ?? features.isIp ? 1 : 0),
        Number(features.has_at_symbol ?? features.hasAtSymbol ? 1 : 0),
        Number(features.num_hyphens ?? features.numHyphens ?? 0),
        Number(features.num_subdomains ?? features.numSubdomains ?? 0),
        Number(features.is_https !== undefined ? (features.is_https ? 1 : 0) : (features.isHttps ? 1 : 0)),
        Number(features.has_double_slash_in_path ?? features.hasDoubleSlashInPath ? 1 : 0),
        Number(features.num_suspicious_keywords ?? features.suspiciousKeywordsCount ?? 0),
        Number(features.has_suspicious_tld ?? features.hasSuspiciousTld ? 1 : 0),
        Number(features.num_query_params ?? features.numQueryParams ?? 0),
        Number(features.special_char_count ?? features.specialCharCount ?? 0),
        Number(features.domain_entropy ?? features.domainEntropy ?? 0)
      ];
    }
    return new Array(14).fill(0);
  }

  /**
   * Evaluates features and returns class probabilities [prob_legitimate, prob_phishing].
   * @param {number[] | object} features
   * @returns {number[]}
   */
  function predictProba(features) {
    const safeInput = sanitizeInput(features);
    return score(safeInput);
  }

  /**
   * Evaluates features and returns phishing risk probability float [0.0, 1.0].
   * @param {number[] | object} features
   * @returns {number}
   */
  function predictPhishingScore(features) {
    const proba = predictProba(features);
    // proba[1] is the phishing probability from the random forest ensemble
    const scoreVal = typeof proba[1] === 'number' && !isNaN(proba[1]) ? proba[1] : 0.0;
    return Number(scoreVal.toFixed(4));
  }

  return {
    MODEL_VERSION,
    FEATURE_NAMES,
    score,
    predictProba,
    predictPhishingScore
  };
});
