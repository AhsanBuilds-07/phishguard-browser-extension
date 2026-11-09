/**
 * SentinelAI: Phishing & Scam Link Shield
 * Pre-Trained Machine Learning Model (Random Forest Ensemble)
 *
 * Generated via m2cgen transpiler from scikit-learn RandomForestClassifier.
 * Pure mathematical inference with ZERO external dependencies.
 *
 * Evaluation Metrics on Unseen Held-Out Domains:
 *   - Accuracy:            98.90%
 *   - Precision:           99.40%
 *   - Recall:              98.24%
 *   - F1-Score:            98.82%
 *   - ROC-AUC:             0.9994
 *   - False Positive Rate: 0.51%
 *   - False Negative Rate: 1.76%
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
  const MODEL_VERSION = "rf-20261106-104021-9a89f8";

  function score(input) {
    var var0;
    if (input[7] <= 0.5) {
        if (input[9] <= 0.5) {
            if (input[1] <= 8.5) {
                if (input[11] <= 0.5) {
                    var0 = [1.0, 0.0];
                } else {
                    var0 = [0.6666666666666666, 0.3333333333333333];
                }
            } else {
                if (input[2] <= 2.5) {
                    if (input[1] <= 19.5) {
                        if (input[5] <= 1.5) {
                            if (input[0] <= 36.5) {
                                var0 = [0.8841463414634146, 0.11585365853658537];
                            } else {
                                var0 = [0.19548872180451127, 0.8045112781954887];
                            }
                        } else {
                            var0 = [0.0, 1.0];
                        }
                    } else {
                        if (input[10] <= 0.5) {
                            if (input[8] <= 0.5) {
                                var0 = [0.12393162393162394, 0.8760683760683761];
                            } else {
                                var0 = [0.0, 1.0];
                            }
                        } else {
                            var0 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[12] <= 0.5) {
                        if (input[13] <= 3.1894999742507935) {
                            if (input[0] <= 26.5) {
                                var0 = [0.25, 0.75];
                            } else {
                                var0 = [0.0, 1.0];
                            }
                        } else {
                            if (input[1] <= 19.5) {
                                var0 = [1.0, 0.0];
                            } else {
                                var0 = [0.022727272727272728, 0.9772727272727273];
                            }
                        }
                    } else {
                        var0 = [0.0, 1.0];
                    }
                }
            }
        } else {
            if (input[12] <= 0.5) {
                if (input[2] <= 1.5) {
                    if (input[5] <= 0.5) {
                        if (input[0] <= 36.5) {
                            if (input[0] <= 30.5) {
                                var0 = [1.0, 0.0];
                            } else {
                                var0 = [0.6666666666666666, 0.3333333333333333];
                            }
                        } else {
                            if (input[13] <= 3.559000015258789) {
                                var0 = [0.0, 1.0];
                            } else {
                                var0 = [0.5, 0.5];
                            }
                        }
                    } else {
                        var0 = [0.0, 1.0];
                    }
                } else {
                    if (input[3] <= 0.5) {
                        if (input[1] <= 19.5) {
                            var0 = [1.0, 0.0];
                        } else {
                            if (input[2] <= 2.5) {
                                var0 = [0.006968641114982578, 0.9930313588850174];
                            } else {
                                var0 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var0 = [0.0, 1.0];
                    }
                }
            } else {
                var0 = [0.0, 1.0];
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
                    if (input[2] <= 3.5) {
                        if (input[0] <= 60.5) {
                            if (input[6] <= 1.5) {
                                var1 = [0.9519621109607578, 0.04803788903924222];
                            } else {
                                var1 = [0.8939393939393939, 0.10606060606060606];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var1 = [0.011111111111111112, 0.9888888888888889];
                            } else {
                                var1 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[2] <= 5.5) {
                            if (input[0] <= 44.0) {
                                var1 = [1.0, 0.0];
                            } else {
                                var1 = [0.14285714285714285, 0.8571428571428571];
                            }
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
                if (input[2] <= 2.5) {
                    if (input[12] <= 0.5) {
                        if (input[13] <= 3.265000104904175) {
                            var1 = [0.7222222222222222, 0.2777777777777778];
                        } else {
                            if (input[0] <= 39.5) {
                                var1 = [0.8571428571428571, 0.14285714285714285];
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
                var1 = [1.0, 0.0];
            }
        }
    } else {
        var1 = [0.0, 1.0];
    }
    var var2;
    if (input[12] <= 2.5) {
        if (input[2] <= 2.5) {
            if (input[9] <= 0.5) {
                if (input[1] <= 19.5) {
                    if (input[7] <= 0.5) {
                        if (input[0] <= 33.5) {
                            if (input[2] <= 1.5) {
                                var2 = [0.872093023255814, 0.12790697674418605];
                            } else {
                                var2 = [0.9571428571428572, 0.04285714285714286];
                            }
                        } else {
                            if (input[0] <= 54.5) {
                                var2 = [0.39655172413793105, 0.603448275862069];
                            } else {
                                var2 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var2 = [1.0, 0.0];
                    }
                } else {
                    if (input[7] <= 0.5) {
                        if (input[12] <= 0.5) {
                            if (input[10] <= 0.5) {
                                var2 = [0.1693548387096774, 0.8306451612903226];
                            } else {
                                var2 = [0.0, 1.0];
                            }
                        } else {
                            if (input[13] <= 3.7335000038146973) {
                                var2 = [0.0, 1.0];
                            } else {
                                var2 = [0.08333333333333333, 0.9166666666666666];
                            }
                        }
                    } else {
                        var2 = [1.0, 0.0];
                    }
                }
            } else {
                if (input[12] <= 0.5) {
                    if (input[0] <= 46.5) {
                        if (input[2] <= 1.5) {
                            if (input[5] <= 1.5) {
                                var2 = [0.96, 0.04];
                            } else {
                                var2 = [0.0, 1.0];
                            }
                        } else {
                            var2 = [1.0, 0.0];
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            var2 = [0.0, 1.0];
                        } else {
                            var2 = [1.0, 0.0];
                        }
                    }
                } else {
                    var2 = [0.0, 1.0];
                }
            }
        } else {
            if (input[0] <= 28.5) {
                if (input[6] <= 1.0) {
                    var2 = [0.0, 1.0];
                } else {
                    var2 = [1.0, 0.0];
                }
            } else {
                if (input[6] <= 1.0) {
                    var2 = [0.0, 1.0];
                } else {
                    if (input[0] <= 41.5) {
                        if (input[13] <= 3.805000066757202) {
                            var2 = [1.0, 0.0];
                        } else {
                            var2 = [0.5, 0.5];
                        }
                    } else {
                        if (input[0] <= 60.5) {
                            if (input[2] <= 3.5) {
                                var2 = [0.625, 0.375];
                            } else {
                                var2 = [0.1111111111111111, 0.8888888888888888];
                            }
                        } else {
                            if (input[0] <= 68.5) {
                                var2 = [0.16666666666666666, 0.8333333333333334];
                            } else {
                                var2 = [0.0, 1.0];
                            }
                        }
                    }
                }
            }
        }
    } else {
        var2 = [0.0, 1.0];
    }
    var var3;
    if (input[0] <= 40.5) {
        if (input[6] <= 0.5) {
            if (input[2] <= 2.0) {
                if (input[10] <= 0.5) {
                    if (input[0] <= 33.5) {
                        if (input[13] <= 2.9394999742507935) {
                            if (input[7] <= 0.5) {
                                var3 = [0.8979591836734694, 0.10204081632653061];
                            } else {
                                var3 = [1.0, 0.0];
                            }
                        } else {
                            if (input[9] <= 0.5) {
                                var3 = [0.9985272459499264, 0.0014727540500736377];
                            } else {
                                var3 = [0.9850746268656716, 0.014925373134328358];
                            }
                        }
                    } else {
                        if (input[1] <= 12.5) {
                            if (input[0] <= 39.5) {
                                var3 = [0.9655172413793104, 0.034482758620689655];
                            } else {
                                var3 = [0.7333333333333333, 0.26666666666666666];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var3 = [0.3333333333333333, 0.6666666666666666];
                            } else {
                                var3 = [1.0, 0.0];
                            }
                        }
                    }
                } else {
                    var3 = [0.25, 0.75];
                }
            } else {
                var3 = [0.0, 1.0];
            }
        } else {
            if (input[6] <= 1.5) {
                if (input[5] <= 2.5) {
                    if (input[12] <= 0.5) {
                        if (input[7] <= 0.5) {
                            if (input[9] <= 0.5) {
                                var3 = [0.8939393939393939, 0.10606060606060606];
                            } else {
                                var3 = [1.0, 0.0];
                            }
                        } else {
                            var3 = [1.0, 0.0];
                        }
                    } else {
                        var3 = [0.5, 0.5];
                    }
                } else {
                    var3 = [0.0, 1.0];
                }
            } else {
                if (input[9] <= 0.5) {
                    if (input[2] <= 4.0) {
                        if (input[0] <= 32.5) {
                            var3 = [1.0, 0.0];
                        } else {
                            if (input[0] <= 33.5) {
                                var3 = [0.8, 0.2];
                            } else {
                                var3 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var3 = [1.0, 0.0];
                    }
                } else {
                    var3 = [1.0, 0.0];
                }
            }
        }
    } else {
        if (input[0] <= 57.5) {
            if (input[7] <= 0.5) {
                if (input[1] <= 15.5) {
                    if (input[3] <= 0.5) {
                        if (input[2] <= 1.5) {
                            if (input[10] <= 0.5) {
                                var3 = [0.19047619047619047, 0.8095238095238095];
                            } else {
                                var3 = [0.0, 1.0];
                            }
                        } else {
                            var3 = [1.0, 0.0];
                        }
                    } else {
                        var3 = [0.0, 1.0];
                    }
                } else {
                    if (input[1] <= 18.5) {
                        if (input[6] <= 0.5) {
                            if (input[1] <= 17.5) {
                                var3 = [0.25, 0.75];
                            } else {
                                var3 = [0.5, 0.5];
                            }
                        } else {
                            if (input[1] <= 16.5) {
                                var3 = [0.6666666666666666, 0.3333333333333333];
                            } else {
                                var3 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[5] <= 1.5) {
                            if (input[0] <= 49.5) {
                                var3 = [0.0, 1.0];
                            } else {
                                var3 = [0.17073170731707318, 0.8292682926829268];
                            }
                        } else {
                            var3 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var3 = [1.0, 0.0];
            }
        } else {
            if (input[1] <= 20.5) {
                var3 = [0.0, 1.0];
            } else {
                if (input[1] <= 23.5) {
                    if (input[12] <= 0.5) {
                        if (input[7] <= 0.5) {
                            if (input[6] <= 0.5) {
                                var3 = [0.0, 1.0];
                            } else {
                                var3 = [0.25, 0.75];
                            }
                        } else {
                            var3 = [1.0, 0.0];
                        }
                    } else {
                        if (input[11] <= 0.5) {
                            var3 = [0.0, 1.0];
                        } else {
                            if (input[0] <= 61.0) {
                                var3 = [1.0, 0.0];
                            } else {
                                var3 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[0] <= 62.5) {
                        if (input[9] <= 0.5) {
                            if (input[0] <= 61.5) {
                                var3 = [0.4444444444444444, 0.5555555555555556];
                            } else {
                                var3 = [1.0, 0.0];
                            }
                        } else {
                            var3 = [0.0, 1.0];
                        }
                    } else {
                        var3 = [0.0, 1.0];
                    }
                }
            }
        }
    }
    var var4;
    if (input[1] <= 11.5) {
        if (input[12] <= 0.5) {
            if (input[0] <= 48.5) {
                if (input[3] <= 0.5) {
                    if (input[0] <= 23.5) {
                        var4 = [1.0, 0.0];
                    } else {
                        if (input[7] <= 0.5) {
                            if (input[9] <= 1.5) {
                                var4 = [0.7916666666666666, 0.20833333333333334];
                            } else {
                                var4 = [0.5, 0.5];
                            }
                        } else {
                            var4 = [1.0, 0.0];
                        }
                    }
                } else {
                    var4 = [0.0, 1.0];
                }
            } else {
                var4 = [0.0, 1.0];
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[2] <= 1.5) {
                    if (input[13] <= 2.9739999771118164) {
                        if (input[0] <= 39.5) {
                            var4 = [0.6666666666666666, 0.3333333333333333];
                        } else {
                            var4 = [0.0, 1.0];
                        }
                    } else {
                        if (input[13] <= 3.146000027656555) {
                            var4 = [0.0, 1.0];
                        } else {
                            if (input[11] <= 0.5) {
                                var4 = [0.0, 1.0];
                            } else {
                                var4 = [0.5, 0.5];
                            }
                        }
                    }
                } else {
                    if (input[13] <= 2.89300000667572) {
                        var4 = [0.0, 1.0];
                    } else {
                        var4 = [0.5, 0.5];
                    }
                }
            } else {
                var4 = [1.0, 0.0];
            }
        }
    } else {
        if (input[13] <= 3.009500026702881) {
            if (input[2] <= 2.5) {
                if (input[1] <= 22.5) {
                    if (input[2] <= 1.5) {
                        if (input[13] <= 2.6054999828338623) {
                            var4 = [0.3333333333333333, 0.6666666666666666];
                        } else {
                            if (input[11] <= 0.5) {
                                var4 = [0.8421052631578947, 0.15789473684210525];
                            } else {
                                var4 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var4 = [1.0, 0.0];
                    }
                } else {
                    var4 = [0.0, 1.0];
                }
            } else {
                if (input[1] <= 15.5) {
                    if (input[9] <= 0.5) {
                        if (input[6] <= 1.0) {
                            var4 = [0.0, 1.0];
                        } else {
                            var4 = [1.0, 0.0];
                        }
                    } else {
                        if (input[4] <= 0.5) {
                            if (input[0] <= 32.5) {
                                var4 = [0.16666666666666666, 0.8333333333333334];
                            } else {
                                var4 = [0.0, 1.0];
                            }
                        } else {
                            var4 = [0.0, 1.0];
                        }
                    }
                } else {
                    var4 = [1.0, 0.0];
                }
            }
        } else {
            if (input[0] <= 59.5) {
                if (input[7] <= 0.5) {
                    if (input[3] <= 0.5) {
                        if (input[1] <= 17.5) {
                            if (input[0] <= 35.5) {
                                var4 = [0.9583333333333334, 0.041666666666666664];
                            } else {
                                var4 = [0.4418604651162791, 0.5581395348837209];
                            }
                        } else {
                            if (input[11] <= 0.5) {
                                var4 = [0.24571428571428572, 0.7542857142857143];
                            } else {
                                var4 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var4 = [0.0, 1.0];
                    }
                } else {
                    var4 = [1.0, 0.0];
                }
            } else {
                if (input[9] <= 0.5) {
                    if (input[0] <= 64.5) {
                        if (input[13] <= 3.620500087738037) {
                            if (input[1] <= 23.5) {
                                var4 = [0.0, 1.0];
                            } else {
                                var4 = [0.4, 0.6];
                            }
                        } else {
                            if (input[0] <= 60.5) {
                                var4 = [0.0, 1.0];
                            } else {
                                var4 = [0.6, 0.4];
                            }
                        }
                    } else {
                        var4 = [0.0, 1.0];
                    }
                } else {
                    var4 = [0.0, 1.0];
                }
            }
        }
    }
    var var5;
    if (input[7] <= 0.5) {
        if (input[1] <= 11.5) {
            if (input[12] <= 0.5) {
                if (input[2] <= 2.5) {
                    if (input[13] <= 2.728500008583069) {
                        if (input[6] <= 0.5) {
                            if (input[1] <= 8.0) {
                                var5 = [1.0, 0.0];
                            } else {
                                var5 = [0.8333333333333334, 0.16666666666666666];
                            }
                        } else {
                            var5 = [1.0, 0.0];
                        }
                    } else {
                        if (input[2] <= 1.5) {
                            var5 = [0.7021276595744681, 0.2978723404255319];
                        } else {
                            var5 = [1.0, 0.0];
                        }
                    }
                } else {
                    var5 = [0.0, 1.0];
                }
            } else {
                if (input[13] <= 2.9739999771118164) {
                    if (input[1] <= 10.0) {
                        var5 = [0.5, 0.5];
                    } else {
                        if (input[13] <= 2.8230000734329224) {
                            var5 = [0.25, 0.75];
                        } else {
                            var5 = [0.0, 1.0];
                        }
                    }
                } else {
                    var5 = [0.0, 1.0];
                }
            }
        } else {
            if (input[12] <= 0.5) {
                if (input[13] <= 3.0479999780654907) {
                    if (input[6] <= 0.5) {
                        if (input[1] <= 12.5) {
                            if (input[2] <= 2.0) {
                                var5 = [0.4, 0.6];
                            } else {
                                var5 = [0.0, 1.0];
                            }
                        } else {
                            if (input[2] <= 2.0) {
                                var5 = [0.125, 0.875];
                            } else {
                                var5 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[0] <= 36.0) {
                            var5 = [1.0, 0.0];
                        } else {
                            var5 = [0.6666666666666666, 0.3333333333333333];
                        }
                    }
                } else {
                    if (input[0] <= 36.5) {
                        if (input[0] <= 32.5) {
                            if (input[1] <= 12.5) {
                                var5 = [0.5, 0.5];
                            } else {
                                var5 = [1.0, 0.0];
                            }
                        } else {
                            if (input[13] <= 3.8545000553131104) {
                                var5 = [0.6190476190476191, 0.38095238095238093];
                            } else {
                                var5 = [0.2, 0.8];
                            }
                        }
                    } else {
                        if (input[0] <= 44.5) {
                            if (input[6] <= 0.5) {
                                var5 = [0.08823529411764706, 0.9117647058823529];
                            } else {
                                var5 = [0.2727272727272727, 0.7272727272727273];
                            }
                        } else {
                            if (input[13] <= 3.708500027656555) {
                                var5 = [0.0, 1.0];
                            } else {
                                var5 = [0.056179775280898875, 0.9438202247191011];
                            }
                        }
                    }
                }
            } else {
                if (input[13] <= 3.009500026702881) {
                    var5 = [0.0, 1.0];
                } else {
                    if (input[6] <= 1.5) {
                        if (input[9] <= 0.5) {
                            if (input[12] <= 1.5) {
                                var5 = [0.0, 1.0];
                            } else {
                                var5 = [0.14606741573033707, 0.8539325842696629];
                            }
                        } else {
                            var5 = [0.0, 1.0];
                        }
                    } else {
                        var5 = [0.0, 1.0];
                    }
                }
            }
        }
    } else {
        var5 = [1.0, 0.0];
    }
    var var6;
    if (input[0] <= 41.5) {
        if (input[7] <= 0.5) {
            if (input[9] <= 1.5) {
                if (input[3] <= 0.5) {
                    if (input[1] <= 22.5) {
                        if (input[9] <= 0.5) {
                            if (input[12] <= 0.5) {
                                var6 = [0.8369098712446352, 0.1630901287553648];
                            } else {
                                var6 = [0.3, 0.7];
                            }
                        } else {
                            if (input[0] <= 39.0) {
                                var6 = [0.8, 0.2];
                            } else {
                                var6 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[5] <= 2.0) {
                            var6 = [0.7222222222222222, 0.2777777777777778];
                        } else {
                            var6 = [0.0, 1.0];
                        }
                    }
                } else {
                    var6 = [0.0, 1.0];
                }
            } else {
                if (input[13] <= 3.021999955177307) {
                    var6 = [0.5, 0.5];
                } else {
                    var6 = [1.0, 0.0];
                }
            }
        } else {
            var6 = [1.0, 0.0];
        }
    } else {
        if (input[2] <= 2.5) {
            if (input[7] <= 0.5) {
                if (input[11] <= 0.5) {
                    if (input[5] <= 0.5) {
                        if (input[12] <= 0.5) {
                            if (input[1] <= 19.0) {
                                var6 = [0.12195121951219512, 0.8780487804878049];
                            } else {
                                var6 = [0.005449591280653951, 0.9945504087193461];
                            }
                        } else {
                            var6 = [0.0, 1.0];
                        }
                    } else {
                        var6 = [0.0, 1.0];
                    }
                } else {
                    if (input[0] <= 61.5) {
                        if (input[0] <= 51.0) {
                            var6 = [1.0, 0.0];
                        } else {
                            if (input[6] <= 0.5) {
                                var6 = [0.6666666666666666, 0.3333333333333333];
                            } else {
                                var6 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var6 = [0.0, 1.0];
                    }
                }
            } else {
                var6 = [1.0, 0.0];
            }
        } else {
            if (input[3] <= 0.5) {
                if (input[5] <= 0.5) {
                    if (input[12] <= 2.5) {
                        if (input[0] <= 63.0) {
                            if (input[6] <= 2.5) {
                                var6 = [0.875, 0.125];
                            } else {
                                var6 = [0.5, 0.5];
                            }
                        } else {
                            var6 = [0.0, 1.0];
                        }
                    } else {
                        var6 = [0.0, 1.0];
                    }
                } else {
                    var6 = [0.0, 1.0];
                }
            } else {
                var6 = [0.0, 1.0];
            }
        }
    }
    var var7;
    if (input[0] <= 40.5) {
        if (input[0] <= 29.5) {
            if (input[7] <= 0.5) {
                if (input[1] <= 13.5) {
                    if (input[1] <= 11.5) {
                        if (input[0] <= 23.5) {
                            var7 = [1.0, 0.0];
                        } else {
                            if (input[0] <= 27.5) {
                                var7 = [0.7, 0.3];
                            } else {
                                var7 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[6] <= 0.5) {
                            if (input[1] <= 12.5) {
                                var7 = [0.5217391304347826, 0.4782608695652174];
                            } else {
                                var7 = [0.4, 0.6];
                            }
                        } else {
                            var7 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[13] <= 2.9839999675750732) {
                        var7 = [0.3333333333333333, 0.6666666666666666];
                    } else {
                        var7 = [1.0, 0.0];
                    }
                }
            } else {
                var7 = [1.0, 0.0];
            }
        } else {
            if (input[13] <= 3.0479999780654907) {
                if (input[1] <= 11.5) {
                    if (input[7] <= 0.5) {
                        if (input[0] <= 35.5) {
                            if (input[2] <= 1.5) {
                                var7 = [0.6666666666666666, 0.3333333333333333];
                            } else {
                                var7 = [0.8, 0.2];
                            }
                        } else {
                            if (input[13] <= 2.930999994277954) {
                                var7 = [0.0, 1.0];
                            } else {
                                var7 = [0.3333333333333333, 0.6666666666666666];
                            }
                        }
                    } else {
                        var7 = [1.0, 0.0];
                    }
                } else {
                    if (input[2] <= 2.5) {
                        var7 = [0.8947368421052632, 0.10526315789473684];
                    } else {
                        if (input[7] <= 0.5) {
                            var7 = [0.0, 1.0];
                        } else {
                            var7 = [1.0, 0.0];
                        }
                    }
                }
            } else {
                if (input[1] <= 24.5) {
                    if (input[3] <= 0.5) {
                        if (input[13] <= 3.853500008583069) {
                            if (input[11] <= 0.5) {
                                var7 = [0.9598715890850722, 0.04012841091492777];
                            } else {
                                var7 = [0.5, 0.5];
                            }
                        } else {
                            if (input[5] <= 1.0) {
                                var7 = [0.8181818181818182, 0.18181818181818182];
                            } else {
                                var7 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var7 = [0.0, 1.0];
                    }
                } else {
                    if (input[1] <= 27.5) {
                        if (input[0] <= 35.5) {
                            var7 = [1.0, 0.0];
                        } else {
                            if (input[7] <= 0.5) {
                                var7 = [0.0, 1.0];
                            } else {
                                var7 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var7 = [1.0, 0.0];
                    }
                }
            }
        }
    } else {
        if (input[3] <= 0.5) {
            if (input[7] <= 0.5) {
                if (input[13] <= 3.6549999713897705) {
                    if (input[9] <= 0.5) {
                        if (input[0] <= 41.5) {
                            var7 = [1.0, 0.0];
                        } else {
                            if (input[0] <= 59.5) {
                                var7 = [0.2222222222222222, 0.7777777777777778];
                            } else {
                                var7 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[13] <= 3.562999963760376) {
                            var7 = [0.0, 1.0];
                        } else {
                            if (input[1] <= 21.5) {
                                var7 = [0.2857142857142857, 0.7142857142857143];
                            } else {
                                var7 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[1] <= 18.5) {
                        if (input[12] <= 2.5) {
                            if (input[5] <= 0.5) {
                                var7 = [0.5714285714285714, 0.42857142857142855];
                            } else {
                                var7 = [0.0, 1.0];
                            }
                        } else {
                            var7 = [0.0, 1.0];
                        }
                    } else {
                        if (input[12] <= 2.5) {
                            if (input[1] <= 22.5) {
                                var7 = [0.0, 1.0];
                            } else {
                                var7 = [0.01764705882352941, 0.9823529411764705];
                            }
                        } else {
                            var7 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var7 = [1.0, 0.0];
            }
        } else {
            var7 = [0.0, 1.0];
        }
    }
    var var8;
    if (input[0] <= 40.5) {
        if (input[3] <= 0.5) {
            if (input[5] <= 1.5) {
                if (input[13] <= 3.8899999856948853) {
                    if (input[10] <= 0.5) {
                        if (input[0] <= 33.5) {
                            if (input[6] <= 0.5) {
                                var8 = [0.9924559932942163, 0.0075440067057837385];
                            } else {
                                var8 = [1.0, 0.0];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var8 = [0.4074074074074074, 0.5925925925925926];
                            } else {
                                var8 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var8 = [0.125, 0.875];
                    }
                } else {
                    var8 = [0.6, 0.4];
                }
            } else {
                if (input[7] <= 0.5) {
                    if (input[0] <= 36.5) {
                        var8 = [0.0, 1.0];
                    } else {
                        var8 = [0.5, 0.5];
                    }
                } else {
                    var8 = [1.0, 0.0];
                }
            }
        } else {
            var8 = [0.0, 1.0];
        }
    } else {
        if (input[6] <= 0.5) {
            if (input[2] <= 2.0) {
                if (input[4] <= 0.5) {
                    if (input[1] <= 20.5) {
                        if (input[12] <= 2.5) {
                            if (input[7] <= 0.5) {
                                var8 = [0.11827956989247312, 0.8817204301075269];
                            } else {
                                var8 = [1.0, 0.0];
                            }
                        } else {
                            var8 = [0.0, 1.0];
                        }
                    } else {
                        if (input[10] <= 0.5) {
                            if (input[1] <= 29.5) {
                                var8 = [0.65, 0.35];
                            } else {
                                var8 = [0.0, 1.0];
                            }
                        } else {
                            var8 = [0.0, 1.0];
                        }
                    }
                } else {
                    var8 = [0.0, 1.0];
                }
            } else {
                var8 = [0.0, 1.0];
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[13] <= 3.6190000772476196) {
                    if (input[1] <= 19.5) {
                        var8 = [0.4090909090909091, 0.5909090909090909];
                    } else {
                        if (input[13] <= 3.436500072479248) {
                            if (input[12] <= 1.5) {
                                var8 = [0.017543859649122806, 0.9824561403508771];
                            } else {
                                var8 = [0.23076923076923078, 0.7692307692307693];
                            }
                        } else {
                            var8 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[9] <= 0.5) {
                        if (input[13] <= 3.7955000400543213) {
                            if (input[12] <= 0.5) {
                                var8 = [0.11538461538461539, 0.8846153846153846];
                            } else {
                                var8 = [0.029411764705882353, 0.9705882352941176];
                            }
                        } else {
                            var8 = [0.0, 1.0];
                        }
                    } else {
                        var8 = [0.0, 1.0];
                    }
                }
            } else {
                var8 = [1.0, 0.0];
            }
        }
    }
    var var9;
    if (input[3] <= 0.5) {
        if (input[0] <= 56.5) {
            if (input[0] <= 46.5) {
                if (input[2] <= 2.5) {
                    if (input[1] <= 19.5) {
                        if (input[10] <= 0.5) {
                            if (input[13] <= 2.9049999713897705) {
                                var9 = [0.9950576606260296, 0.004942339373970346];
                            } else {
                                var9 = [0.9793205317577548, 0.0206794682422452];
                            }
                        } else {
                            if (input[1] <= 13.5) {
                                var9 = [0.3333333333333333, 0.6666666666666666];
                            } else {
                                var9 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[6] <= 0.5) {
                            if (input[5] <= 1.5) {
                                var9 = [0.9245283018867925, 0.07547169811320754];
                            } else {
                                var9 = [0.5, 0.5];
                            }
                        } else {
                            if (input[13] <= 3.850000023841858) {
                                var9 = [0.9377777777777778, 0.06222222222222222];
                            } else {
                                var9 = [0.5789473684210527, 0.42105263157894735];
                            }
                        }
                    }
                } else {
                    if (input[6] <= 2.5) {
                        var9 = [0.9435483870967742, 0.056451612903225805];
                    } else {
                        if (input[13] <= 3.6024999618530273) {
                            var9 = [0.6666666666666666, 0.3333333333333333];
                        } else {
                            var9 = [1.0, 0.0];
                        }
                    }
                }
            } else {
                if (input[10] <= 0.5) {
                    if (input[1] <= 19.5) {
                        if (input[1] <= 9.5) {
                            var9 = [0.0, 1.0];
                        } else {
                            if (input[1] <= 16.5) {
                                var9 = [0.989247311827957, 0.010752688172043012];
                            } else {
                                var9 = [0.8181818181818182, 0.18181818181818182];
                            }
                        }
                    } else {
                        if (input[12] <= 1.5) {
                            if (input[0] <= 51.5) {
                                var9 = [0.425, 0.575];
                            } else {
                                var9 = [0.0, 1.0];
                            }
                        } else {
                            if (input[0] <= 52.5) {
                                var9 = [0.8181818181818182, 0.18181818181818182];
                            } else {
                                var9 = [1.0, 0.0];
                            }
                        }
                    }
                } else {
                    var9 = [0.0, 1.0];
                }
            }
        } else {
            if (input[0] <= 60.5) {
                if (input[9] <= 0.5) {
                    if (input[11] <= 0.5) {
                        if (input[0] <= 57.5) {
                            if (input[6] <= 0.5) {
                                var9 = [0.0, 1.0];
                            } else {
                                var9 = [0.2, 0.8];
                            }
                        } else {
                            if (input[1] <= 20.5) {
                                var9 = [0.0, 1.0];
                            } else {
                                var9 = [0.8181818181818182, 0.18181818181818182];
                            }
                        }
                    } else {
                        var9 = [1.0, 0.0];
                    }
                } else {
                    var9 = [0.0, 1.0];
                }
            } else {
                if (input[1] <= 23.5) {
                    var9 = [0.0, 1.0];
                } else {
                    if (input[1] <= 25.5) {
                        if (input[0] <= 62.5) {
                            if (input[6] <= 2.0) {
                                var9 = [1.0, 0.0];
                            } else {
                                var9 = [0.0, 1.0];
                            }
                        } else {
                            var9 = [0.0, 1.0];
                        }
                    } else {
                        if (input[1] <= 28.5) {
                            if (input[6] <= 1.5) {
                                var9 = [0.21428571428571427, 0.7857142857142857];
                            } else {
                                var9 = [0.0, 1.0];
                            }
                        } else {
                            if (input[11] <= 0.5) {
                                var9 = [0.0, 1.0];
                            } else {
                                var9 = [0.009900990099009901, 0.9900990099009901];
                            }
                        }
                    }
                }
            }
        }
    } else {
        var9 = [0.0, 1.0];
    }
    var var10;
    if (input[3] <= 0.5) {
        if (input[1] <= 19.5) {
            if (input[11] <= 1.5) {
                if (input[7] <= 0.5) {
                    if (input[10] <= 0.5) {
                        if (input[5] <= 0.5) {
                            if (input[13] <= 3.3769999742507935) {
                                var10 = [0.7023809523809523, 0.2976190476190476];
                            } else {
                                var10 = [0.4326923076923077, 0.5673076923076923];
                            }
                        } else {
                            if (input[0] <= 29.5) {
                                var10 = [1.0, 0.0];
                            } else {
                                var10 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[2] <= 1.5) {
                            var10 = [0.0, 1.0];
                        } else {
                            var10 = [0.5, 0.5];
                        }
                    }
                } else {
                    var10 = [1.0, 0.0];
                }
            } else {
                var10 = [0.0, 1.0];
            }
        } else {
            if (input[13] <= 3.218000054359436) {
                if (input[9] <= 0.5) {
                    var10 = [0.5, 0.5];
                } else {
                    var10 = [0.0, 1.0];
                }
            } else {
                if (input[9] <= 0.5) {
                    if (input[13] <= 3.8364999294281006) {
                        if (input[0] <= 46.5) {
                            if (input[1] <= 20.5) {
                                var10 = [0.868421052631579, 0.13157894736842105];
                            } else {
                                var10 = [0.949748743718593, 0.05025125628140704];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var10 = [0.046052631578947366, 0.9539473684210527];
                            } else {
                                var10 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[5] <= 2.5) {
                            if (input[12] <= 0.5) {
                                var10 = [0.3191489361702128, 0.6808510638297872];
                            } else {
                                var10 = [0.02, 0.98];
                            }
                        } else {
                            if (input[13] <= 3.992500066757202) {
                                var10 = [0.0, 1.0];
                            } else {
                                var10 = [0.3333333333333333, 0.6666666666666666];
                            }
                        }
                    }
                } else {
                    if (input[12] <= 0.5) {
                        if (input[1] <= 20.5) {
                            if (input[9] <= 1.5) {
                                var10 = [0.16, 0.84];
                            } else {
                                var10 = [0.034482758620689655, 0.9655172413793104];
                            }
                        } else {
                            if (input[1] <= 24.5) {
                                var10 = [0.6451612903225806, 0.3548387096774194];
                            } else {
                                var10 = [0.07692307692307693, 0.9230769230769231];
                            }
                        }
                    } else {
                        var10 = [0.0, 1.0];
                    }
                }
            }
        }
    } else {
        var10 = [0.0, 1.0];
    }
    var var11;
    if (input[13] <= 2.9049999713897705) {
        if (input[2] <= 2.5) {
            if (input[1] <= 22.5) {
                if (input[1] <= 10.5) {
                    if (input[13] <= 2.6134999990463257) {
                        var11 = [1.0, 0.0];
                    } else {
                        if (input[1] <= 7.5) {
                            var11 = [1.0, 0.0];
                        } else {
                            if (input[9] <= 1.5) {
                                var11 = [0.9940119760479041, 0.005988023952095809];
                            } else {
                                var11 = [0.8181818181818182, 0.18181818181818182];
                            }
                        }
                    }
                } else {
                    if (input[6] <= 0.5) {
                        if (input[13] <= 2.742000102996826) {
                            var11 = [0.8333333333333334, 0.16666666666666666];
                        } else {
                            if (input[1] <= 11.5) {
                                var11 = [0.9166666666666666, 0.08333333333333333];
                            } else {
                                var11 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var11 = [1.0, 0.0];
                    }
                }
            } else {
                var11 = [0.0, 1.0];
            }
        } else {
            if (input[7] <= 0.5) {
                var11 = [0.0, 1.0];
            } else {
                var11 = [1.0, 0.0];
            }
        }
    } else {
        if (input[11] <= 1.5) {
            if (input[7] <= 0.5) {
                if (input[11] <= 0.5) {
                    if (input[13] <= 3.6355000734329224) {
                        if (input[0] <= 38.5) {
                            if (input[2] <= 2.5) {
                                var11 = [0.8724489795918368, 0.12755102040816327];
                            } else {
                                var11 = [0.25, 0.75];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var11 = [0.0027472527472527475, 0.9972527472527473];
                            } else {
                                var11 = [0.024096385542168676, 0.9759036144578314];
                            }
                        }
                    } else {
                        if (input[0] <= 36.5) {
                            if (input[5] <= 1.5) {
                                var11 = [1.0, 0.0];
                            } else {
                                var11 = [0.0, 1.0];
                            }
                        } else {
                            if (input[0] <= 38.0) {
                                var11 = [0.3333333333333333, 0.6666666666666666];
                            } else {
                                var11 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[1] <= 20.5) {
                        if (input[1] <= 8.5) {
                            var11 = [0.0, 1.0];
                        } else {
                            if (input[2] <= 2.5) {
                                var11 = [0.42857142857142855, 0.5714285714285714];
                            } else {
                                var11 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[12] <= 2.5) {
                            if (input[1] <= 24.5) {
                                var11 = [0.14285714285714285, 0.8571428571428571];
                            } else {
                                var11 = [0.0, 1.0];
                            }
                        } else {
                            var11 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var11 = [1.0, 0.0];
            }
        } else {
            var11 = [0.0, 1.0];
        }
    }
    var var12;
    if (input[7] <= 0.5) {
        if (input[2] <= 2.5) {
            if (input[1] <= 18.5) {
                if (input[12] <= 0.5) {
                    if (input[2] <= 1.5) {
                        if (input[9] <= 0.5) {
                            if (input[13] <= 2.8259999752044678) {
                                var12 = [0.9714285714285714, 0.02857142857142857];
                            } else {
                                var12 = [0.5523809523809524, 0.44761904761904764];
                            }
                        } else {
                            if (input[5] <= 0.5) {
                                var12 = [0.45454545454545453, 0.5454545454545454];
                            } else {
                                var12 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[1] <= 15.5) {
                            var12 = [0.9382716049382716, 0.06172839506172839];
                        } else {
                            if (input[13] <= 3.5640000104904175) {
                                var12 = [0.8709677419354839, 0.12903225806451613];
                            } else {
                                var12 = [0.4, 0.6];
                            }
                        }
                    }
                } else {
                    if (input[5] <= 0.5) {
                        if (input[9] <= 0.5) {
                            if (input[1] <= 15.5) {
                                var12 = [0.10638297872340426, 0.8936170212765957];
                            } else {
                                var12 = [0.5714285714285714, 0.42857142857142855];
                            }
                        } else {
                            var12 = [0.0, 1.0];
                        }
                    } else {
                        var12 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[5] <= 0.5) {
                    if (input[11] <= 0.5) {
                        if (input[13] <= 3.784500002861023) {
                            if (input[0] <= 38.5) {
                                var12 = [0.9166666666666666, 0.08333333333333333];
                            } else {
                                var12 = [0.0018018018018018018, 0.9981981981981982];
                            }
                        } else {
                            if (input[2] <= 1.5) {
                                var12 = [0.6, 0.4];
                            } else {
                                var12 = [0.14893617021276595, 0.851063829787234];
                            }
                        }
                    } else {
                        if (input[1] <= 20.5) {
                            var12 = [0.6363636363636364, 0.36363636363636365];
                        } else {
                            var12 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[0] <= 32.5) {
                        var12 = [1.0, 0.0];
                    } else {
                        if (input[11] <= 0.5) {
                            if (input[10] <= 0.5) {
                                var12 = [0.041666666666666664, 0.9583333333333334];
                            } else {
                                var12 = [0.0, 1.0];
                            }
                        } else {
                            if (input[9] <= 0.5) {
                                var12 = [1.0, 0.0];
                            } else {
                                var12 = [0.0, 1.0];
                            }
                        }
                    }
                }
            }
        } else {
            if (input[6] <= 1.0) {
                var12 = [0.0, 1.0];
            } else {
                if (input[13] <= 3.3904999494552612) {
                    var12 = [1.0, 0.0];
                } else {
                    if (input[5] <= 0.5) {
                        if (input[6] <= 2.5) {
                            if (input[13] <= 3.587999939918518) {
                                var12 = [0.6, 0.4];
                            } else {
                                var12 = [0.013888888888888888, 0.9861111111111112];
                            }
                        } else {
                            var12 = [0.0, 1.0];
                        }
                    } else {
                        var12 = [0.0, 1.0];
                    }
                }
            }
        }
    } else {
        var12 = [1.0, 0.0];
    }
    var var13;
    if (input[7] <= 0.5) {
        if (input[0] <= 28.5) {
            if (input[0] <= 23.5) {
                if (input[6] <= 0.5) {
                    if (input[13] <= 2.652999997138977) {
                        if (input[1] <= 8.0) {
                            var13 = [1.0, 0.0];
                        } else {
                            var13 = [0.75, 0.25];
                        }
                    } else {
                        var13 = [1.0, 0.0];
                    }
                } else {
                    var13 = [1.0, 0.0];
                }
            } else {
                if (input[13] <= 3.1755000352859497) {
                    if (input[9] <= 1.0) {
                        if (input[3] <= 0.5) {
                            if (input[13] <= 3.038999915122986) {
                                var13 = [0.5714285714285714, 0.42857142857142855];
                            } else {
                                var13 = [0.4, 0.6];
                            }
                        } else {
                            var13 = [0.0, 1.0];
                        }
                    } else {
                        var13 = [1.0, 0.0];
                    }
                } else {
                    if (input[2] <= 1.5) {
                        if (input[1] <= 14.5) {
                            var13 = [0.5, 0.5];
                        } else {
                            var13 = [1.0, 0.0];
                        }
                    } else {
                        var13 = [1.0, 0.0];
                    }
                }
            }
        } else {
            if (input[13] <= 2.885499954223633) {
                if (input[13] <= 2.447499990463257) {
                    if (input[11] <= 0.5) {
                        var13 = [0.011111111111111112, 0.9888888888888889];
                    } else {
                        var13 = [0.0, 1.0];
                    }
                } else {
                    if (input[2] <= 2.5) {
                        if (input[0] <= 46.0) {
                            if (input[0] <= 32.0) {
                                var13 = [0.4, 0.6];
                            } else {
                                var13 = [0.75, 0.25];
                            }
                        } else {
                            var13 = [0.0, 1.0];
                        }
                    } else {
                        var13 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[6] <= 1.5) {
                    if (input[0] <= 42.5) {
                        if (input[3] <= 0.5) {
                            if (input[0] <= 33.5) {
                                var13 = [0.8372093023255814, 0.16279069767441862];
                            } else {
                                var13 = [0.41904761904761906, 0.580952380952381];
                            }
                        } else {
                            var13 = [0.0, 1.0];
                        }
                    } else {
                        if (input[0] <= 61.5) {
                            if (input[2] <= 2.5) {
                                var13 = [0.21935483870967742, 0.7806451612903226];
                            } else {
                                var13 = [0.0, 1.0];
                            }
                        } else {
                            if (input[0] <= 62.5) {
                                var13 = [0.058823529411764705, 0.9411764705882353];
                            } else {
                                var13 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[13] <= 3.4399999380111694) {
                        var13 = [0.7142857142857143, 0.2857142857142857];
                    } else {
                        if (input[5] <= 0.5) {
                            if (input[2] <= 3.5) {
                                var13 = [0.014285714285714285, 0.9857142857142858];
                            } else {
                                var13 = [0.0, 1.0];
                            }
                        } else {
                            var13 = [0.0, 1.0];
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
        if (input[13] <= 3.6829999685287476) {
            if (input[1] <= 19.5) {
                if (input[5] <= 1.5) {
                    if (input[0] <= 57.5) {
                        if (input[7] <= 0.5) {
                            if (input[12] <= 0.5) {
                                var14 = [0.7974683544303798, 0.20253164556962025];
                            } else {
                                var14 = [0.24489795918367346, 0.7551020408163265];
                            }
                        } else {
                            var14 = [1.0, 0.0];
                        }
                    } else {
                        var14 = [0.0, 1.0];
                    }
                } else {
                    if (input[1] <= 16.5) {
                        var14 = [0.5, 0.5];
                    } else {
                        if (input[0] <= 42.5) {
                            var14 = [0.5, 0.5];
                        } else {
                            var14 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                if (input[12] <= 0.5) {
                    if (input[13] <= 3.5845000743865967) {
                        if (input[2] <= 1.5) {
                            if (input[9] <= 0.5) {
                                var14 = [0.8823529411764706, 0.11764705882352941];
                            } else {
                                var14 = [0.5, 0.5];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var14 = [0.04950495049504951, 0.9504950495049505];
                            } else {
                                var14 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[0] <= 49.5) {
                            if (input[2] <= 1.5) {
                                var14 = [0.9285714285714286, 0.07142857142857142];
                            } else {
                                var14 = [1.0, 0.0];
                            }
                        } else {
                            var14 = [0.4, 0.6];
                        }
                    }
                } else {
                    if (input[9] <= 0.5) {
                        if (input[11] <= 0.5) {
                            var14 = [0.0, 1.0];
                        } else {
                            if (input[0] <= 61.0) {
                                var14 = [1.0, 0.0];
                            } else {
                                var14 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var14 = [0.0, 1.0];
                    }
                }
            }
        } else {
            if (input[1] <= 19.5) {
                if (input[11] <= 0.5) {
                    if (input[0] <= 43.5) {
                        var14 = [1.0, 0.0];
                    } else {
                        if (input[13] <= 3.7664999961853027) {
                            var14 = [0.25, 0.75];
                        } else {
                            var14 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[0] <= 66.0) {
                        var14 = [1.0, 0.0];
                    } else {
                        var14 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[7] <= 0.5) {
                    if (input[9] <= 0.5) {
                        if (input[2] <= 1.5) {
                            if (input[0] <= 44.5) {
                                var14 = [0.25, 0.75];
                            } else {
                                var14 = [0.0, 1.0];
                            }
                        } else {
                            if (input[1] <= 28.5) {
                                var14 = [0.16455696202531644, 0.8354430379746836];
                            } else {
                                var14 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var14 = [0.0, 1.0];
                    }
                } else {
                    var14 = [1.0, 0.0];
                }
            }
        }
    } else {
        if (input[3] <= 0.5) {
            if (input[13] <= 3.6920000314712524) {
                if (input[6] <= 2.5) {
                    if (input[0] <= 53.5) {
                        var14 = [1.0, 0.0];
                    } else {
                        var14 = [0.3333333333333333, 0.6666666666666666];
                    }
                } else {
                    var14 = [0.06666666666666667, 0.9333333333333333];
                }
            } else {
                if (input[0] <= 41.5) {
                    var14 = [1.0, 0.0];
                } else {
                    if (input[2] <= 4.5) {
                        if (input[1] <= 24.5) {
                            var14 = [0.3, 0.7];
                        } else {
                            var14 = [0.0, 1.0];
                        }
                    } else {
                        var14 = [0.0, 1.0];
                    }
                }
            }
        } else {
            var14 = [0.0, 1.0];
        }
    }
    var var15;
    if (input[0] <= 40.5) {
        if (input[13] <= 2.9049999713897705) {
            if (input[6] <= 0.5) {
                if (input[2] <= 2.0) {
                    if (input[5] <= 0.5) {
                        if (input[7] <= 0.5) {
                            if (input[13] <= 2.5535000562667847) {
                                var15 = [1.0, 0.0];
                            } else {
                                var15 = [0.55, 0.45];
                            }
                        } else {
                            var15 = [1.0, 0.0];
                        }
                    } else {
                        var15 = [1.0, 0.0];
                    }
                } else {
                    var15 = [0.0, 1.0];
                }
            } else {
                var15 = [1.0, 0.0];
            }
        } else {
            if (input[3] <= 0.5) {
                if (input[5] <= 1.5) {
                    if (input[10] <= 0.5) {
                        if (input[13] <= 3.8899999856948853) {
                            if (input[1] <= 14.5) {
                                var15 = [0.973661852166525, 0.026338147833474938];
                            } else {
                                var15 = [0.9897674418604652, 0.010232558139534883];
                            }
                        } else {
                            if (input[5] <= 0.5) {
                                var15 = [0.6153846153846154, 0.38461538461538464];
                            } else {
                                var15 = [0.5714285714285714, 0.42857142857142855];
                            }
                        }
                    } else {
                        var15 = [0.3333333333333333, 0.6666666666666666];
                    }
                } else {
                    if (input[0] <= 31.5) {
                        var15 = [1.0, 0.0];
                    } else {
                        if (input[1] <= 23.0) {
                            var15 = [0.3333333333333333, 0.6666666666666666];
                        } else {
                            var15 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var15 = [0.0, 1.0];
            }
        }
    } else {
        if (input[3] <= 0.5) {
            if (input[6] <= 1.5) {
                if (input[9] <= 0.5) {
                    if (input[11] <= 0.5) {
                        if (input[2] <= 1.5) {
                            if (input[12] <= 0.5) {
                                var15 = [0.6836734693877551, 0.3163265306122449];
                            } else {
                                var15 = [0.0, 1.0];
                            }
                        } else {
                            if (input[5] <= 1.5) {
                                var15 = [0.44357976653696496, 0.556420233463035];
                            } else {
                                var15 = [0.09090909090909091, 0.9090909090909091];
                            }
                        }
                    } else {
                        if (input[12] <= 2.5) {
                            if (input[0] <= 60.5) {
                                var15 = [1.0, 0.0];
                            } else {
                                var15 = [0.0, 1.0];
                            }
                        } else {
                            var15 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[13] <= 3.7050000429153442) {
                        if (input[13] <= 3.572999954223633) {
                            if (input[6] <= 0.5) {
                                var15 = [0.004016064257028112, 0.9959839357429718];
                            } else {
                                var15 = [0.10810810810810811, 0.8918918918918919];
                            }
                        } else {
                            var15 = [0.0, 1.0];
                        }
                    } else {
                        if (input[2] <= 1.5) {
                            var15 = [0.0, 1.0];
                        } else {
                            if (input[0] <= 60.5) {
                                var15 = [0.5, 0.5];
                            } else {
                                var15 = [0.0, 1.0];
                            }
                        }
                    }
                }
            } else {
                if (input[13] <= 3.5460000038146973) {
                    if (input[7] <= 0.5) {
                        var15 = [0.0, 1.0];
                    } else {
                        var15 = [1.0, 0.0];
                    }
                } else {
                    if (input[6] <= 3.5) {
                        if (input[1] <= 24.5) {
                            if (input[0] <= 69.0) {
                                var15 = [0.3125, 0.6875];
                            } else {
                                var15 = [0.0, 1.0];
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
            var15 = [0.0, 1.0];
        }
    }
    var var16;
    if (input[13] <= 2.909000039100647) {
        if (input[2] <= 2.5) {
            if (input[10] <= 0.5) {
                if (input[13] <= 2.305000066757202) {
                    if (input[1] <= 10.5) {
                        var16 = [1.0, 0.0];
                    } else {
                        var16 = [0.3333333333333333, 0.6666666666666666];
                    }
                } else {
                    if (input[7] <= 0.5) {
                        if (input[0] <= 51.0) {
                            if (input[0] <= 26.5) {
                                var16 = [1.0, 0.0];
                            } else {
                                var16 = [0.9166666666666666, 0.08333333333333333];
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
                    var16 = [0.0, 1.0];
                } else {
                    var16 = [1.0, 0.0];
                }
            } else {
                if (input[3] <= 0.5) {
                    var16 = [1.0, 0.0];
                } else {
                    var16 = [0.0, 1.0];
                }
            }
        }
    } else {
        if (input[1] <= 19.5) {
            if (input[7] <= 0.5) {
                if (input[6] <= 0.5) {
                    if (input[3] <= 0.5) {
                        if (input[5] <= 0.5) {
                            if (input[12] <= 0.5) {
                                var16 = [0.5639097744360902, 0.43609022556390975];
                            } else {
                                var16 = [0.09259259259259259, 0.9074074074074074];
                            }
                        } else {
                            if (input[9] <= 0.5) {
                                var16 = [0.07692307692307693, 0.9230769230769231];
                            } else {
                                var16 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var16 = [0.0, 1.0];
                    }
                } else {
                    if (input[13] <= 3.5964999198913574) {
                        if (input[13] <= 3.3874999284744263) {
                            if (input[2] <= 2.5) {
                                var16 = [0.8918918918918919, 0.10810810810810811];
                            } else {
                                var16 = [1.0, 0.0];
                            }
                        } else {
                            if (input[1] <= 14.5) {
                                var16 = [0.1111111111111111, 0.8888888888888888];
                            } else {
                                var16 = [0.9523809523809523, 0.047619047619047616];
                            }
                        }
                    } else {
                        if (input[13] <= 3.7044999599456787) {
                            var16 = [0.0, 1.0];
                        } else {
                            var16 = [0.4, 0.6];
                        }
                    }
                }
            } else {
                var16 = [1.0, 0.0];
            }
        } else {
            if (input[10] <= 0.5) {
                if (input[7] <= 0.5) {
                    if (input[6] <= 0.5) {
                        if (input[5] <= 0.5) {
                            if (input[13] <= 3.559499979019165) {
                                var16 = [0.0, 1.0];
                            } else {
                                var16 = [0.16666666666666666, 0.8333333333333334];
                            }
                        } else {
                            if (input[0] <= 41.0) {
                                var16 = [0.5, 0.5];
                            } else {
                                var16 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[6] <= 1.5) {
                            if (input[9] <= 0.5) {
                                var16 = [0.09569377990430622, 0.9043062200956937];
                            } else {
                                var16 = [0.005235602094240838, 0.9947643979057592];
                            }
                        } else {
                            if (input[2] <= 3.5) {
                                var16 = [0.011363636363636364, 0.9886363636363636];
                            } else {
                                var16 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    var16 = [1.0, 0.0];
                }
            } else {
                var16 = [0.0, 1.0];
            }
        }
    }
    var var17;
    if (input[9] <= 0.5) {
        if (input[12] <= 2.5) {
            if (input[1] <= 11.5) {
                if (input[7] <= 0.5) {
                    if (input[0] <= 39.5) {
                        if (input[13] <= 2.484000086784363) {
                            if (input[3] <= 0.5) {
                                var17 = [1.0, 0.0];
                            } else {
                                var17 = [0.0, 1.0];
                            }
                        } else {
                            var17 = [0.8714285714285714, 0.12857142857142856];
                        }
                    } else {
                        if (input[11] <= 0.5) {
                            var17 = [0.0, 1.0];
                        } else {
                            var17 = [1.0, 0.0];
                        }
                    }
                } else {
                    var17 = [1.0, 0.0];
                }
            } else {
                if (input[3] <= 0.5) {
                    if (input[0] <= 62.5) {
                        if (input[6] <= 2.5) {
                            if (input[12] <= 1.5) {
                                var17 = [0.9411449973247726, 0.05885500267522739];
                            } else {
                                var17 = [0.9831460674157303, 0.016853932584269662];
                            }
                        } else {
                            var17 = [0.2916666666666667, 0.7083333333333334];
                        }
                    } else {
                        if (input[5] <= 0.5) {
                            if (input[6] <= 1.5) {
                                var17 = [0.008620689655172414, 0.9913793103448276];
                            } else {
                                var17 = [0.0, 1.0];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var17 = [0.0, 1.0];
                            } else {
                                var17 = [1.0, 0.0];
                            }
                        }
                    }
                } else {
                    var17 = [0.0, 1.0];
                }
            }
        } else {
            var17 = [0.0, 1.0];
        }
    } else {
        if (input[0] <= 40.5) {
            if (input[3] <= 0.5) {
                if (input[13] <= 3.3240000009536743) {
                    var17 = [1.0, 0.0];
                } else {
                    if (input[13] <= 3.347000002861023) {
                        var17 = [0.3333333333333333, 0.6666666666666666];
                    } else {
                        var17 = [1.0, 0.0];
                    }
                }
            } else {
                var17 = [0.0, 1.0];
            }
        } else {
            if (input[13] <= 3.325500011444092) {
                var17 = [0.0, 1.0];
            } else {
                if (input[5] <= 0.5) {
                    if (input[7] <= 0.5) {
                        if (input[2] <= 1.5) {
                            if (input[4] <= 0.5) {
                                var17 = [0.041666666666666664, 0.9583333333333334];
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
                    if (input[6] <= 0.5) {
                        var17 = [0.0, 1.0];
                    } else {
                        if (input[0] <= 73.5) {
                            var17 = [0.5, 0.5];
                        } else {
                            var17 = [0.0, 1.0];
                        }
                    }
                }
            }
        }
    }
    var var18;
    if (input[0] <= 40.5) {
        if (input[0] <= 29.5) {
            if (input[13] <= 3.028999924659729) {
                if (input[1] <= 11.5) {
                    if (input[0] <= 25.5) {
                        var18 = [1.0, 0.0];
                    } else {
                        if (input[1] <= 9.5) {
                            var18 = [1.0, 0.0];
                        } else {
                            if (input[6] <= 0.5) {
                                var18 = [0.9473684210526315, 0.05263157894736842];
                            } else {
                                var18 = [1.0, 0.0];
                            }
                        }
                    }
                } else {
                    if (input[6] <= 0.5) {
                        if (input[7] <= 0.5) {
                            if (input[0] <= 23.0) {
                                var18 = [1.0, 0.0];
                            } else {
                                var18 = [0.0, 1.0];
                            }
                        } else {
                            var18 = [1.0, 0.0];
                        }
                    } else {
                        var18 = [1.0, 0.0];
                    }
                }
            } else {
                if (input[1] <= 12.5) {
                    var18 = [0.983739837398374, 0.016260162601626018];
                } else {
                    var18 = [1.0, 0.0];
                }
            }
        } else {
            if (input[13] <= 2.9394999742507935) {
                if (input[7] <= 0.5) {
                    if (input[13] <= 2.8844999074935913) {
                        if (input[2] <= 2.5) {
                            if (input[1] <= 9.5) {
                                var18 = [0.5, 0.5];
                            } else {
                                var18 = [0.8, 0.2];
                            }
                        } else {
                            var18 = [0.0, 1.0];
                        }
                    } else {
                        if (input[13] <= 2.9199999570846558) {
                            if (input[0] <= 33.5) {
                                var18 = [0.0, 1.0];
                            } else {
                                var18 = [0.625, 0.375];
                            }
                        } else {
                            if (input[1] <= 11.5) {
                                var18 = [0.2, 0.8];
                            } else {
                                var18 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    var18 = [1.0, 0.0];
                }
            } else {
                if (input[7] <= 0.5) {
                    if (input[3] <= 0.5) {
                        if (input[0] <= 36.5) {
                            if (input[5] <= 1.5) {
                                var18 = [0.7872340425531915, 0.2127659574468085];
                            } else {
                                var18 = [0.0, 1.0];
                            }
                        } else {
                            if (input[5] <= 2.5) {
                                var18 = [0.2619047619047619, 0.7380952380952381];
                            } else {
                                var18 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var18 = [0.0, 1.0];
                    }
                } else {
                    var18 = [1.0, 0.0];
                }
            }
        }
    } else {
        if (input[3] <= 0.5) {
            if (input[13] <= 3.643499970436096) {
                if (input[0] <= 54.5) {
                    if (input[7] <= 0.5) {
                        if (input[0] <= 42.5) {
                            if (input[9] <= 0.5) {
                                var18 = [0.9090909090909091, 0.09090909090909091];
                            } else {
                                var18 = [0.3333333333333333, 0.6666666666666666];
                            }
                        } else {
                            if (input[12] <= 1.5) {
                                var18 = [0.016129032258064516, 0.9838709677419355];
                            } else {
                                var18 = [0.4827586206896552, 0.5172413793103449];
                            }
                        }
                    } else {
                        var18 = [1.0, 0.0];
                    }
                } else {
                    if (input[1] <= 19.5) {
                        if (input[11] <= 0.5) {
                            if (input[1] <= 16.5) {
                                var18 = [0.0, 1.0];
                            } else {
                                var18 = [0.16666666666666666, 0.8333333333333334];
                            }
                        } else {
                            if (input[0] <= 59.5) {
                                var18 = [1.0, 0.0];
                            } else {
                                var18 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            var18 = [0.0, 1.0];
                        } else {
                            var18 = [1.0, 0.0];
                        }
                    }
                }
            } else {
                if (input[1] <= 18.5) {
                    if (input[0] <= 61.0) {
                        var18 = [1.0, 0.0];
                    } else {
                        var18 = [0.0, 1.0];
                    }
                } else {
                    if (input[13] <= 3.6864999532699585) {
                        if (input[1] <= 21.0) {
                            var18 = [0.022304832713754646, 0.9776951672862454];
                        } else {
                            var18 = [0.5, 0.5];
                        }
                    } else {
                        if (input[13] <= 3.75600004196167) {
                            if (input[2] <= 2.5) {
                                var18 = [0.72, 0.28];
                            } else {
                                var18 = [0.2, 0.8];
                            }
                        } else {
                            if (input[9] <= 0.5) {
                                var18 = [0.10576923076923077, 0.8942307692307693];
                            } else {
                                var18 = [0.0, 1.0];
                            }
                        }
                    }
                }
            }
        } else {
            var18 = [0.0, 1.0];
        }
    }
    var var19;
    if (input[12] <= 2.5) {
        if (input[2] <= 2.5) {
            if (input[9] <= 0.5) {
                if (input[6] <= 0.5) {
                    if (input[1] <= 30.5) {
                        if (input[12] <= 0.5) {
                            if (input[0] <= 47.5) {
                                var19 = [0.9780736100234926, 0.02192638997650744];
                            } else {
                                var19 = [0.2571428571428571, 0.7428571428571429];
                            }
                        } else {
                            if (input[0] <= 51.5) {
                                var19 = [0.9419354838709677, 0.05806451612903226];
                            } else {
                                var19 = [0.5777777777777777, 0.4222222222222222];
                            }
                        }
                    } else {
                        var19 = [0.0, 1.0];
                    }
                } else {
                    if (input[7] <= 0.5) {
                        if (input[1] <= 19.5) {
                            if (input[11] <= 0.5) {
                                var19 = [0.797979797979798, 0.20202020202020202];
                            } else {
                                var19 = [1.0, 0.0];
                            }
                        } else {
                            if (input[13] <= 3.790500044822693) {
                                var19 = [0.14655172413793102, 0.853448275862069];
                            } else {
                                var19 = [0.023529411764705882, 0.9764705882352941];
                            }
                        }
                    } else {
                        var19 = [1.0, 0.0];
                    }
                }
            } else {
                if (input[0] <= 47.5) {
                    if (input[7] <= 0.5) {
                        if (input[10] <= 0.5) {
                            if (input[13] <= 3.280500054359436) {
                                var19 = [1.0, 0.0];
                            } else {
                                var19 = [0.625, 0.375];
                            }
                        } else {
                            var19 = [0.0, 1.0];
                        }
                    } else {
                        var19 = [1.0, 0.0];
                    }
                } else {
                    var19 = [0.0, 1.0];
                }
            }
        } else {
            if (input[3] <= 0.5) {
                if (input[1] <= 21.5) {
                    if (input[7] <= 0.5) {
                        if (input[9] <= 0.5) {
                            var19 = [0.5, 0.5];
                        } else {
                            var19 = [1.0, 0.0];
                        }
                    } else {
                        var19 = [1.0, 0.0];
                    }
                } else {
                    if (input[1] <= 25.5) {
                        if (input[13] <= 3.8170000314712524) {
                            var19 = [0.5454545454545454, 0.45454545454545453];
                        } else {
                            var19 = [0.0, 1.0];
                        }
                    } else {
                        if (input[2] <= 4.5) {
                            if (input[12] <= 0.5) {
                                var19 = [0.14285714285714285, 0.8571428571428571];
                            } else {
                                var19 = [0.09090909090909091, 0.9090909090909091];
                            }
                        } else {
                            var19 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var19 = [0.0, 1.0];
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
