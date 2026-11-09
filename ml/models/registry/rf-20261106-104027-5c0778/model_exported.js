/**
 * SentinelAI: Phishing & Scam Link Shield
 * Pre-Trained Machine Learning Model (Random Forest Ensemble)
 *
 * Generated via m2cgen transpiler from scikit-learn RandomForestClassifier.
 * Pure mathematical inference with ZERO external dependencies.
 *
 * Evaluation Metrics on Unseen Held-Out Domains:
 *   - Accuracy:            98.97%
 *   - Precision:           99.26%
 *   - Recall:              98.53%
 *   - F1-Score:            98.89%
 *   - ROC-AUC:             0.9996
 *   - False Positive Rate: 0.64%
 *   - False Negative Rate: 1.47%
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
  const MODEL_VERSION = "rf-20261106-104027-5c0778";

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
    var var20;
    if (input[3] <= 0.5) {
        if (input[9] <= 0.5) {
            if (input[1] <= 19.5) {
                if (input[0] <= 56.5) {
                    if (input[0] <= 35.5) {
                        var20 = [0.9937076476282671, 0.0062923523717328175];
                    } else {
                        if (input[7] <= 0.5) {
                            if (input[2] <= 1.5) {
                                var20 = [0.2222222222222222, 0.7777777777777778];
                            } else {
                                var20 = [0.6896551724137931, 0.3103448275862069];
                            }
                        } else {
                            var20 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[2] <= 2.5) {
                        var20 = [0.0, 1.0];
                    } else {
                        var20 = [0.5, 0.5];
                    }
                }
            } else {
                if (input[0] <= 42.5) {
                    if (input[1] <= 26.5) {
                        if (input[7] <= 0.5) {
                            if (input[6] <= 0.5) {
                                var20 = [1.0, 0.0];
                            } else {
                                var20 = [0.6818181818181818, 0.3181818181818182];
                            }
                        } else {
                            var20 = [1.0, 0.0];
                        }
                    } else {
                        if (input[2] <= 2.5) {
                            if (input[7] <= 0.5) {
                                var20 = [0.3333333333333333, 0.6666666666666666];
                            } else {
                                var20 = [1.0, 0.0];
                            }
                        } else {
                            if (input[1] <= 29.5) {
                                var20 = [0.75, 0.25];
                            } else {
                                var20 = [1.0, 0.0];
                            }
                        }
                    }
                } else {
                    if (input[0] <= 60.5) {
                        if (input[12] <= 1.5) {
                            if (input[1] <= 20.5) {
                                var20 = [0.25, 0.75];
                            } else {
                                var20 = [0.42857142857142855, 0.5714285714285714];
                            }
                        } else {
                            if (input[13] <= 3.7335000038146973) {
                                var20 = [1.0, 0.0];
                            } else {
                                var20 = [0.8571428571428571, 0.14285714285714285];
                            }
                        }
                    } else {
                        if (input[2] <= 1.5) {
                            var20 = [0.08333333333333333, 0.9166666666666666];
                        } else {
                            if (input[11] <= 0.5) {
                                var20 = [0.006369426751592357, 0.9936305732484076];
                            } else {
                                var20 = [0.011904761904761904, 0.9880952380952381];
                            }
                        }
                    }
                }
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[0] <= 39.5) {
                    if (input[9] <= 1.5) {
                        if (input[1] <= 12.5) {
                            var20 = [1.0, 0.0];
                        } else {
                            if (input[2] <= 1.5) {
                                var20 = [0.42857142857142855, 0.5714285714285714];
                            } else {
                                var20 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var20 = [1.0, 0.0];
                    }
                } else {
                    var20 = [0.0, 1.0];
                }
            } else {
                var20 = [1.0, 0.0];
            }
        }
    } else {
        var20 = [0.0, 1.0];
    }
    var var21;
    if (input[7] <= 0.5) {
        if (input[2] <= 2.5) {
            if (input[13] <= 3.3830000162124634) {
                if (input[12] <= 0.5) {
                    if (input[2] <= 1.5) {
                        if (input[0] <= 36.5) {
                            if (input[13] <= 2.934999942779541) {
                                var21 = [0.85, 0.15];
                            } else {
                                var21 = [0.9523809523809523, 0.047619047619047616];
                            }
                        } else {
                            if (input[0] <= 43.0) {
                                var21 = [0.2857142857142857, 0.7142857142857143];
                            } else {
                                var21 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[1] <= 11.5) {
                            var21 = [1.0, 0.0];
                        } else {
                            var21 = [0.9038461538461539, 0.09615384615384616];
                        }
                    }
                } else {
                    if (input[1] <= 18.5) {
                        if (input[1] <= 11.5) {
                            if (input[0] <= 46.5) {
                                var21 = [0.5294117647058824, 0.47058823529411764];
                            } else {
                                var21 = [0.0, 1.0];
                            }
                        } else {
                            if (input[9] <= 0.5) {
                                var21 = [0.7692307692307693, 0.23076923076923078];
                            } else {
                                var21 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[11] <= 0.5) {
                            var21 = [0.0, 1.0];
                        } else {
                            if (input[9] <= 0.5) {
                                var21 = [0.16666666666666666, 0.8333333333333334];
                            } else {
                                var21 = [0.0, 1.0];
                            }
                        }
                    }
                }
            } else {
                if (input[1] <= 19.5) {
                    if (input[12] <= 2.5) {
                        if (input[2] <= 1.5) {
                            if (input[9] <= 0.5) {
                                var21 = [0.425, 0.575];
                            } else {
                                var21 = [0.1, 0.9];
                            }
                        } else {
                            if (input[1] <= 14.5) {
                                var21 = [0.14285714285714285, 0.8571428571428571];
                            } else {
                                var21 = [0.7222222222222222, 0.2777777777777778];
                            }
                        }
                    } else {
                        var21 = [0.0, 1.0];
                    }
                } else {
                    if (input[11] <= 1.5) {
                        if (input[5] <= 1.5) {
                            if (input[1] <= 20.5) {
                                var21 = [0.010498687664041995, 0.989501312335958];
                            } else {
                                var21 = [0.11643835616438356, 0.8835616438356164];
                            }
                        } else {
                            var21 = [0.0, 1.0];
                        }
                    } else {
                        var21 = [0.0, 1.0];
                    }
                }
            }
        } else {
            if (input[12] <= 0.5) {
                if (input[6] <= 1.0) {
                    var21 = [0.0, 1.0];
                } else {
                    if (input[1] <= 21.5) {
                        var21 = [1.0, 0.0];
                    } else {
                        var21 = [0.0, 1.0];
                    }
                }
            } else {
                var21 = [0.0, 1.0];
            }
        }
    } else {
        var21 = [1.0, 0.0];
    }
    var var22;
    if (input[2] <= 2.5) {
        if (input[10] <= 0.5) {
            if (input[11] <= 1.5) {
                if (input[0] <= 60.5) {
                    if (input[1] <= 19.5) {
                        if (input[2] <= 1.5) {
                            if (input[0] <= 47.5) {
                                var22 = [0.9716859716859717, 0.028314028314028315];
                            } else {
                                var22 = [0.6307692307692307, 0.36923076923076925];
                            }
                        } else {
                            if (input[0] <= 42.5) {
                                var22 = [0.9982683982683983, 0.0017316017316017316];
                            } else {
                                var22 = [0.9732142857142857, 0.026785714285714284];
                            }
                        }
                    } else {
                        if (input[12] <= 1.5) {
                            if (input[0] <= 36.5) {
                                var22 = [0.9815668202764977, 0.018433179723502304];
                            } else {
                                var22 = [0.582010582010582, 0.41798941798941797];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var22 = [0.8333333333333334, 0.16666666666666666];
                            } else {
                                var22 = [1.0, 0.0];
                            }
                        }
                    }
                } else {
                    if (input[1] <= 23.5) {
                        var22 = [0.0, 1.0];
                    } else {
                        if (input[0] <= 64.5) {
                            if (input[9] <= 0.5) {
                                var22 = [0.7142857142857143, 0.2857142857142857];
                            } else {
                                var22 = [0.0, 1.0];
                            }
                        } else {
                            var22 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var22 = [0.0, 1.0];
            }
        } else {
            if (input[12] <= 0.5) {
                if (input[1] <= 14.5) {
                    var22 = [0.5, 0.5];
                } else {
                    var22 = [0.0, 1.0];
                }
            } else {
                var22 = [0.0, 1.0];
            }
        }
    } else {
        if (input[0] <= 28.5) {
            if (input[13] <= 2.801500082015991) {
                var22 = [0.0, 1.0];
            } else {
                if (input[5] <= 0.5) {
                    if (input[1] <= 13.5) {
                        var22 = [0.8, 0.2];
                    } else {
                        var22 = [1.0, 0.0];
                    }
                } else {
                    var22 = [1.0, 0.0];
                }
            }
        } else {
            if (input[0] <= 41.5) {
                if (input[7] <= 0.5) {
                    if (input[6] <= 1.0) {
                        var22 = [0.0, 1.0];
                    } else {
                        var22 = [0.75, 0.25];
                    }
                } else {
                    var22 = [1.0, 0.0];
                }
            } else {
                if (input[13] <= 3.0774999856948853) {
                    if (input[0] <= 51.5) {
                        if (input[0] <= 50.5) {
                            var22 = [0.0, 1.0];
                        } else {
                            if (input[12] <= 1.0) {
                                var22 = [0.0, 1.0];
                            } else {
                                var22 = [0.3333333333333333, 0.6666666666666666];
                            }
                        }
                    } else {
                        var22 = [0.0, 1.0];
                    }
                } else {
                    if (input[1] <= 23.5) {
                        if (input[1] <= 14.5) {
                            var22 = [0.0, 1.0];
                        } else {
                            if (input[7] <= 0.5) {
                                var22 = [0.0, 1.0];
                            } else {
                                var22 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[2] <= 3.5) {
                            var22 = [0.0, 1.0];
                        } else {
                            if (input[5] <= 0.5) {
                                var22 = [0.0, 1.0];
                            } else {
                                var22 = [0.0625, 0.9375];
                            }
                        }
                    }
                }
            }
        }
    }
    var var23;
    if (input[1] <= 11.5) {
        if (input[0] <= 50.0) {
            if (input[3] <= 0.5) {
                if (input[1] <= 7.5) {
                    var23 = [1.0, 0.0];
                } else {
                    if (input[7] <= 0.5) {
                        if (input[2] <= 1.5) {
                            if (input[0] <= 33.5) {
                                var23 = [0.75, 0.25];
                            } else {
                                var23 = [0.13333333333333333, 0.8666666666666667];
                            }
                        } else {
                            var23 = [1.0, 0.0];
                        }
                    } else {
                        var23 = [1.0, 0.0];
                    }
                }
            } else {
                var23 = [0.0, 1.0];
            }
        } else {
            var23 = [0.0, 1.0];
        }
    } else {
        if (input[13] <= 2.9110000133514404) {
            if (input[6] <= 0.5) {
                if (input[7] <= 0.5) {
                    var23 = [0.0, 1.0];
                } else {
                    var23 = [1.0, 0.0];
                }
            } else {
                if (input[1] <= 35.0) {
                    var23 = [1.0, 0.0];
                } else {
                    var23 = [0.0, 1.0];
                }
            }
        } else {
            if (input[0] <= 59.5) {
                if (input[2] <= 2.5) {
                    if (input[5] <= 1.5) {
                        if (input[0] <= 37.5) {
                            var23 = [0.9857972885732731, 0.014202711426726921];
                        } else {
                            if (input[7] <= 0.5) {
                                var23 = [0.2459016393442623, 0.7540983606557377];
                            } else {
                                var23 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[7] <= 0.5) {
                                var23 = [0.045454545454545456, 0.9545454545454546];
                            } else {
                                var23 = [1.0, 0.0];
                            }
                        } else {
                            var23 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[0] <= 35.5) {
                        if (input[6] <= 1.0) {
                            var23 = [0.0, 1.0];
                        } else {
                            if (input[13] <= 3.787000060081482) {
                                var23 = [1.0, 0.0];
                            } else {
                                var23 = [0.6666666666666666, 0.3333333333333333];
                            }
                        }
                    } else {
                        if (input[3] <= 0.5) {
                            if (input[7] <= 0.5) {
                                var23 = [0.05263157894736842, 0.9473684210526315];
                            } else {
                                var23 = [1.0, 0.0];
                            }
                        } else {
                            var23 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                if (input[0] <= 65.5) {
                    if (input[9] <= 0.5) {
                        if (input[7] <= 0.5) {
                            if (input[11] <= 0.5) {
                                var23 = [0.0, 1.0];
                            } else {
                                var23 = [0.2, 0.8];
                            }
                        } else {
                            var23 = [1.0, 0.0];
                        }
                    } else {
                        var23 = [0.0, 1.0];
                    }
                } else {
                    var23 = [0.0, 1.0];
                }
            }
        }
    }
    var var24;
    if (input[3] <= 0.5) {
        if (input[7] <= 0.5) {
            if (input[4] <= 0.5) {
                if (input[12] <= 0.5) {
                    if (input[1] <= 19.5) {
                        if (input[9] <= 2.5) {
                            if (input[5] <= 0.5) {
                                var24 = [0.7527675276752768, 0.24723247232472326];
                            } else {
                                var24 = [0.15, 0.85];
                            }
                        } else {
                            var24 = [0.0, 1.0];
                        }
                    } else {
                        if (input[0] <= 38.5) {
                            if (input[2] <= 1.5) {
                                var24 = [0.75, 0.25];
                            } else {
                                var24 = [0.7096774193548387, 0.2903225806451613];
                            }
                        } else {
                            if (input[13] <= 3.7165000438690186) {
                                var24 = [0.0, 1.0];
                            } else {
                                var24 = [0.06796116504854369, 0.9320388349514563];
                            }
                        }
                    }
                } else {
                    if (input[0] <= 57.5) {
                        if (input[11] <= 0.5) {
                            var24 = [0.0, 1.0];
                        } else {
                            if (input[0] <= 39.5) {
                                var24 = [0.0, 1.0];
                            } else {
                                var24 = [0.896551724137931, 0.10344827586206896];
                            }
                        }
                    } else {
                        if (input[2] <= 1.5) {
                            var24 = [0.0, 1.0];
                        } else {
                            if (input[5] <= 0.5) {
                                var24 = [0.011627906976744186, 0.9883720930232558];
                            } else {
                                var24 = [0.08823529411764706, 0.9117647058823529];
                            }
                        }
                    }
                }
            } else {
                var24 = [0.0, 1.0];
            }
        } else {
            var24 = [1.0, 0.0];
        }
    } else {
        var24 = [0.0, 1.0];
    }
    var var25;
    if (input[0] <= 40.5) {
        if (input[2] <= 2.5) {
            if (input[0] <= 33.5) {
                if (input[2] <= 1.5) {
                    if (input[5] <= 0.5) {
                        if (input[13] <= 2.9394999742507935) {
                            if (input[9] <= 0.5) {
                                var25 = [0.9736842105263158, 0.02631578947368421];
                            } else {
                                var25 = [1.0, 0.0];
                            }
                        } else {
                            if (input[0] <= 23.5) {
                                var25 = [1.0, 0.0];
                            } else {
                                var25 = [0.9892183288409704, 0.01078167115902965];
                            }
                        }
                    } else {
                        var25 = [1.0, 0.0];
                    }
                } else {
                    if (input[0] <= 27.5) {
                        var25 = [1.0, 0.0];
                    } else {
                        var25 = [0.9880239520958084, 0.011976047904191617];
                    }
                }
            } else {
                if (input[9] <= 0.5) {
                    if (input[5] <= 1.5) {
                        if (input[10] <= 0.5) {
                            if (input[1] <= 10.5) {
                                var25 = [0.9753086419753086, 0.024691358024691357];
                            } else {
                                var25 = [0.9246987951807228, 0.07530120481927711];
                            }
                        } else {
                            var25 = [0.6666666666666666, 0.3333333333333333];
                        }
                    } else {
                        var25 = [0.0, 1.0];
                    }
                } else {
                    if (input[13] <= 2.652999997138977) {
                        var25 = [0.6666666666666666, 0.3333333333333333];
                    } else {
                        var25 = [1.0, 0.0];
                    }
                }
            }
        } else {
            if (input[6] <= 1.0) {
                var25 = [0.0, 1.0];
            } else {
                if (input[13] <= 3.8170000314712524) {
                    var25 = [1.0, 0.0];
                } else {
                    var25 = [0.2, 0.8];
                }
            }
        }
    } else {
        if (input[7] <= 0.5) {
            if (input[1] <= 8.5) {
                if (input[13] <= 2.903499960899353) {
                    var25 = [0.6, 0.4];
                } else {
                    var25 = [0.0, 1.0];
                }
            } else {
                if (input[2] <= 2.5) {
                    if (input[1] <= 19.5) {
                        if (input[11] <= 0.5) {
                            if (input[12] <= 0.5) {
                                var25 = [0.15, 0.85];
                            } else {
                                var25 = [0.0, 1.0];
                            }
                        } else {
                            if (input[0] <= 58.0) {
                                var25 = [1.0, 0.0];
                            } else {
                                var25 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[1] <= 26.5) {
                            if (input[13] <= 3.33650004863739) {
                                var25 = [0.17647058823529413, 0.8235294117647058];
                            } else {
                                var25 = [0.012422360248447204, 0.9875776397515528];
                            }
                        } else {
                            var25 = [0.0, 1.0];
                        }
                    }
                } else {
                    var25 = [0.0, 1.0];
                }
            }
        } else {
            var25 = [1.0, 0.0];
        }
    }
    var var26;
    if (input[13] <= 2.909000039100647) {
        if (input[9] <= 0.5) {
            if (input[3] <= 0.5) {
                if (input[7] <= 0.5) {
                    var26 = [0.9347826086956522, 0.06521739130434782];
                } else {
                    var26 = [1.0, 0.0];
                }
            } else {
                var26 = [0.0, 1.0];
            }
        } else {
            if (input[3] <= 0.5) {
                if (input[12] <= 1.0) {
                    if (input[9] <= 1.5) {
                        if (input[0] <= 36.5) {
                            var26 = [1.0, 0.0];
                        } else {
                            var26 = [0.6666666666666666, 0.3333333333333333];
                        }
                    } else {
                        var26 = [1.0, 0.0];
                    }
                } else {
                    var26 = [0.0, 1.0];
                }
            } else {
                var26 = [0.0, 1.0];
            }
        }
    } else {
        if (input[0] <= 59.5) {
            if (input[1] <= 23.5) {
                if (input[3] <= 0.5) {
                    if (input[5] <= 1.5) {
                        if (input[7] <= 0.5) {
                            if (input[5] <= 0.5) {
                                var26 = [0.6153846153846154, 0.38461538461538464];
                            } else {
                                var26 = [0.75, 0.25];
                            }
                        } else {
                            var26 = [1.0, 0.0];
                        }
                    } else {
                        var26 = [0.21052631578947367, 0.7894736842105263];
                    }
                } else {
                    var26 = [0.0, 1.0];
                }
            } else {
                if (input[6] <= 1.5) {
                    if (input[7] <= 0.5) {
                        if (input[5] <= 0.5) {
                            if (input[10] <= 0.5) {
                                var26 = [0.5333333333333333, 0.4666666666666667];
                            } else {
                                var26 = [0.0, 1.0];
                            }
                        } else {
                            if (input[1] <= 28.0) {
                                var26 = [0.0, 1.0];
                            } else {
                                var26 = [0.16666666666666666, 0.8333333333333334];
                            }
                        }
                    } else {
                        var26 = [1.0, 0.0];
                    }
                } else {
                    if (input[1] <= 31.5) {
                        if (input[0] <= 41.5) {
                            var26 = [1.0, 0.0];
                        } else {
                            var26 = [0.0, 1.0];
                        }
                    } else {
                        var26 = [0.0, 1.0];
                    }
                }
            }
        } else {
            if (input[1] <= 22.5) {
                var26 = [0.0, 1.0];
            } else {
                if (input[0] <= 62.5) {
                    if (input[9] <= 0.5) {
                        if (input[1] <= 24.5) {
                            if (input[12] <= 1.0) {
                                var26 = [1.0, 0.0];
                            } else {
                                var26 = [0.6666666666666666, 0.3333333333333333];
                            }
                        } else {
                            var26 = [0.3333333333333333, 0.6666666666666666];
                        }
                    } else {
                        var26 = [0.0, 1.0];
                    }
                } else {
                    if (input[10] <= 0.5) {
                        if (input[6] <= 1.5) {
                            if (input[12] <= 0.5) {
                                var26 = [0.030303030303030304, 0.9696969696969697];
                            } else {
                                var26 = [0.0, 1.0];
                            }
                        } else {
                            var26 = [0.0, 1.0];
                        }
                    } else {
                        var26 = [0.0, 1.0];
                    }
                }
            }
        }
    }
    var var27;
    if (input[0] <= 40.5) {
        if (input[0] <= 29.5) {
            if (input[2] <= 2.5) {
                if (input[0] <= 27.5) {
                    if (input[7] <= 0.5) {
                        if (input[6] <= 0.5) {
                            if (input[0] <= 25.5) {
                                var27 = [0.984375, 0.015625];
                            } else {
                                var27 = [0.9, 0.1];
                            }
                        } else {
                            var27 = [1.0, 0.0];
                        }
                    } else {
                        var27 = [1.0, 0.0];
                    }
                } else {
                    if (input[1] <= 8.5) {
                        var27 = [0.25, 0.75];
                    } else {
                        if (input[13] <= 2.9199999570846558) {
                            if (input[2] <= 1.5) {
                                var27 = [0.8, 0.2];
                            } else {
                                var27 = [1.0, 0.0];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var27 = [0.96, 0.04];
                            } else {
                                var27 = [1.0, 0.0];
                            }
                        }
                    }
                }
            } else {
                if (input[7] <= 0.5) {
                    if (input[3] <= 0.5) {
                        var27 = [1.0, 0.0];
                    } else {
                        var27 = [0.0, 1.0];
                    }
                } else {
                    var27 = [1.0, 0.0];
                }
            }
        } else {
            if (input[9] <= 1.5) {
                if (input[13] <= 3.0640000104904175) {
                    if (input[3] <= 0.5) {
                        if (input[7] <= 0.5) {
                            var27 = [0.6206896551724138, 0.3793103448275862];
                        } else {
                            var27 = [1.0, 0.0];
                        }
                    } else {
                        var27 = [0.0, 1.0];
                    }
                } else {
                    if (input[7] <= 0.5) {
                        if (input[13] <= 3.8545000553131104) {
                            if (input[0] <= 35.5) {
                                var27 = [0.8048780487804879, 0.1951219512195122];
                            } else {
                                var27 = [0.34375, 0.65625];
                            }
                        } else {
                            var27 = [0.07142857142857142, 0.9285714285714286];
                        }
                    } else {
                        var27 = [1.0, 0.0];
                    }
                }
            } else {
                if (input[0] <= 39.5) {
                    var27 = [1.0, 0.0];
                } else {
                    var27 = [0.75, 0.25];
                }
            }
        }
    } else {
        if (input[0] <= 55.5) {
            if (input[2] <= 2.5) {
                if (input[11] <= 0.5) {
                    if (input[6] <= 0.5) {
                        if (input[9] <= 0.5) {
                            if (input[1] <= 8.5) {
                                var27 = [1.0, 0.0];
                            } else {
                                var27 = [0.5774647887323944, 0.4225352112676056];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var27 = [0.0, 1.0];
                            } else {
                                var27 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[7] <= 0.5) {
                                var27 = [0.20588235294117646, 0.7941176470588235];
                            } else {
                                var27 = [1.0, 0.0];
                            }
                        } else {
                            if (input[0] <= 47.0) {
                                var27 = [1.0, 0.0];
                            } else {
                                var27 = [0.3333333333333333, 0.6666666666666666];
                            }
                        }
                    }
                } else {
                    var27 = [1.0, 0.0];
                }
            } else {
                if (input[5] <= 0.5) {
                    if (input[6] <= 1.0) {
                        var27 = [0.0, 1.0];
                    } else {
                        if (input[13] <= 3.4369999170303345) {
                            var27 = [1.0, 0.0];
                        } else {
                            if (input[7] <= 0.5) {
                                var27 = [0.0, 1.0];
                            } else {
                                var27 = [1.0, 0.0];
                            }
                        }
                    }
                } else {
                    var27 = [0.0, 1.0];
                }
            }
        } else {
            if (input[13] <= 3.4700000286102295) {
                if (input[13] <= 3.0115000009536743) {
                    var27 = [0.0, 1.0];
                } else {
                    if (input[0] <= 56.5) {
                        var27 = [0.6666666666666666, 0.3333333333333333];
                    } else {
                        if (input[1] <= 21.5) {
                            var27 = [0.0, 1.0];
                        } else {
                            if (input[13] <= 3.354499936103821) {
                                var27 = [0.0, 1.0];
                            } else {
                                var27 = [0.03571428571428571, 0.9642857142857143];
                            }
                        }
                    }
                }
            } else {
                if (input[11] <= 0.5) {
                    if (input[2] <= 3.5) {
                        if (input[9] <= 0.5) {
                            if (input[0] <= 59.5) {
                                var27 = [0.6, 0.4];
                            } else {
                                var27 = [0.01652892561983471, 0.9834710743801653];
                            }
                        } else {
                            var27 = [0.0, 1.0];
                        }
                    } else {
                        var27 = [0.0, 1.0];
                    }
                } else {
                    if (input[7] <= 0.5) {
                        if (input[0] <= 62.5) {
                            var27 = [0.6666666666666666, 0.3333333333333333];
                        } else {
                            var27 = [0.0, 1.0];
                        }
                    } else {
                        var27 = [1.0, 0.0];
                    }
                }
            }
        }
    }
    var var28;
    if (input[3] <= 0.5) {
        if (input[0] <= 55.5) {
            if (input[7] <= 0.5) {
                if (input[0] <= 36.5) {
                    if (input[0] <= 25.5) {
                        if (input[6] <= 0.5) {
                            var28 = [0.9846153846153847, 0.015384615384615385];
                        } else {
                            var28 = [1.0, 0.0];
                        }
                    } else {
                        if (input[9] <= 1.5) {
                            if (input[1] <= 10.5) {
                                var28 = [0.4, 0.6];
                            } else {
                                var28 = [0.735632183908046, 0.26436781609195403];
                            }
                        } else {
                            var28 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[0] <= 42.5) {
                        if (input[9] <= 0.5) {
                            if (input[1] <= 14.5) {
                                var28 = [0.625, 0.375];
                            } else {
                                var28 = [0.1875, 0.8125];
                            }
                        } else {
                            var28 = [0.6666666666666666, 0.3333333333333333];
                        }
                    } else {
                        if (input[1] <= 18.5) {
                            if (input[6] <= 0.5) {
                                var28 = [0.11904761904761904, 0.8809523809523809];
                            } else {
                                var28 = [0.8181818181818182, 0.18181818181818182];
                            }
                        } else {
                            if (input[1] <= 22.5) {
                                var28 = [0.0, 1.0];
                            } else {
                                var28 = [0.03571428571428571, 0.9642857142857143];
                            }
                        }
                    }
                }
            } else {
                var28 = [1.0, 0.0];
            }
        } else {
            if (input[11] <= 0.5) {
                if (input[6] <= 2.5) {
                    if (input[7] <= 0.5) {
                        var28 = [0.0, 1.0];
                    } else {
                        var28 = [1.0, 0.0];
                    }
                } else {
                    if (input[13] <= 3.7925000190734863) {
                        if (input[0] <= 57.5) {
                            var28 = [0.0, 1.0];
                        } else {
                            var28 = [0.5, 0.5];
                        }
                    } else {
                        var28 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[12] <= 2.5) {
                    if (input[6] <= 1.5) {
                        if (input[1] <= 27.5) {
                            if (input[0] <= 60.5) {
                                var28 = [1.0, 0.0];
                            } else {
                                var28 = [0.15, 0.85];
                            }
                        } else {
                            var28 = [0.0, 1.0];
                        }
                    } else {
                        var28 = [0.0, 1.0];
                    }
                } else {
                    var28 = [0.0, 1.0];
                }
            }
        }
    } else {
        var28 = [0.0, 1.0];
    }
    var var29;
    if (input[0] <= 41.5) {
        if (input[13] <= 2.843500018119812) {
            if (input[1] <= 11.5) {
                if (input[3] <= 0.5) {
                    if (input[13] <= 2.6134999990463257) {
                        var29 = [1.0, 0.0];
                    } else {
                        if (input[1] <= 8.5) {
                            var29 = [1.0, 0.0];
                        } else {
                            var29 = [0.9920634920634921, 0.007936507936507936];
                        }
                    }
                } else {
                    var29 = [0.0, 1.0];
                }
            } else {
                if (input[6] <= 0.5) {
                    if (input[2] <= 2.0) {
                        if (input[7] <= 0.5) {
                            var29 = [0.5, 0.5];
                        } else {
                            var29 = [1.0, 0.0];
                        }
                    } else {
                        var29 = [0.0, 1.0];
                    }
                } else {
                    var29 = [1.0, 0.0];
                }
            }
        } else {
            if (input[3] <= 0.5) {
                if (input[2] <= 1.5) {
                    if (input[10] <= 0.5) {
                        if (input[1] <= 11.5) {
                            if (input[0] <= 38.5) {
                                var29 = [0.9948186528497409, 0.0051813471502590676];
                            } else {
                                var29 = [0.8125, 0.1875];
                            }
                        } else {
                            var29 = [0.9437086092715232, 0.056291390728476824];
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            var29 = [0.4, 0.6];
                        } else {
                            var29 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[11] <= 0.5) {
                        if (input[5] <= 2.0) {
                            if (input[0] <= 37.5) {
                                var29 = [0.9992012779552716, 0.0007987220447284345];
                            } else {
                                var29 = [0.9174311926605505, 0.08256880733944955];
                            }
                        } else {
                            var29 = [0.0, 1.0];
                        }
                    } else {
                        var29 = [0.4, 0.6];
                    }
                }
            } else {
                var29 = [0.0, 1.0];
            }
        }
    } else {
        if (input[0] <= 58.5) {
            if (input[3] <= 0.5) {
                if (input[5] <= 1.5) {
                    if (input[12] <= 1.5) {
                        if (input[1] <= 19.5) {
                            if (input[1] <= 12.5) {
                                var29 = [0.4339622641509434, 0.5660377358490566];
                            } else {
                                var29 = [0.9423076923076923, 0.057692307692307696];
                            }
                        } else {
                            if (input[9] <= 0.5) {
                                var29 = [0.3592233009708738, 0.6407766990291263];
                            } else {
                                var29 = [0.8571428571428571, 0.14285714285714285];
                            }
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            if (input[1] <= 22.5) {
                                var29 = [0.6176470588235294, 0.38235294117647056];
                            } else {
                                var29 = [0.0, 1.0];
                            }
                        } else {
                            var29 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[13] <= 3.9600000381469727) {
                        var29 = [0.0, 1.0];
                    } else {
                        var29 = [0.25, 0.75];
                    }
                }
            } else {
                var29 = [0.0, 1.0];
            }
        } else {
            if (input[13] <= 3.4285000562667847) {
                var29 = [0.0, 1.0];
            } else {
                if (input[0] <= 59.5) {
                    var29 = [0.875, 0.125];
                } else {
                    if (input[13] <= 3.4415000677108765) {
                        var29 = [0.3333333333333333, 0.6666666666666666];
                    } else {
                        if (input[13] <= 3.7029999494552612) {
                            var29 = [0.0, 1.0];
                        } else {
                            if (input[0] <= 62.5) {
                                var29 = [0.8333333333333334, 0.16666666666666666];
                            } else {
                                var29 = [0.00398406374501992, 0.9960159362549801];
                            }
                        }
                    }
                }
            }
        }
    }
    var var30;
    if (input[12] <= 0.5) {
        if (input[1] <= 11.5) {
            if (input[6] <= 0.5) {
                if (input[7] <= 0.5) {
                    if (input[13] <= 2.778499960899353) {
                        if (input[1] <= 7.5) {
                            var30 = [1.0, 0.0];
                        } else {
                            if (input[0] <= 20.0) {
                                var30 = [1.0, 0.0];
                            } else {
                                var30 = [0.017241379310344827, 0.9827586206896551];
                            }
                        }
                    } else {
                        if (input[1] <= 9.5) {
                            if (input[13] <= 3.059000015258789) {
                                var30 = [1.0, 0.0];
                            } else {
                                var30 = [0.8333333333333334, 0.16666666666666666];
                            }
                        } else {
                            if (input[9] <= 1.0) {
                                var30 = [0.6363636363636364, 0.36363636363636365];
                            } else {
                                var30 = [0.6666666666666666, 0.3333333333333333];
                            }
                        }
                    }
                } else {
                    var30 = [1.0, 0.0];
                }
            } else {
                var30 = [1.0, 0.0];
            }
        } else {
            if (input[6] <= 0.5) {
                if (input[7] <= 0.5) {
                    if (input[3] <= 0.5) {
                        if (input[9] <= 0.5) {
                            if (input[5] <= 1.5) {
                                var30 = [0.5679012345679012, 0.43209876543209874];
                            } else {
                                var30 = [0.1, 0.9];
                            }
                        } else {
                            if (input[10] <= 0.5) {
                                var30 = [0.3125, 0.6875];
                            } else {
                                var30 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var30 = [0.0, 1.0];
                    }
                } else {
                    var30 = [1.0, 0.0];
                }
            } else {
                if (input[0] <= 51.5) {
                    if (input[5] <= 2.5) {
                        if (input[5] <= 1.5) {
                            if (input[7] <= 0.5) {
                                var30 = [0.7210884353741497, 0.2789115646258503];
                            } else {
                                var30 = [1.0, 0.0];
                            }
                        } else {
                            var30 = [0.5, 0.5];
                        }
                    } else {
                        var30 = [0.0, 1.0];
                    }
                } else {
                    if (input[7] <= 0.5) {
                        if (input[6] <= 1.5) {
                            var30 = [0.005934718100890208, 0.9940652818991098];
                        } else {
                            var30 = [0.0, 1.0];
                        }
                    } else {
                        var30 = [1.0, 0.0];
                    }
                }
            }
        }
    } else {
        if (input[7] <= 0.5) {
            if (input[6] <= 0.5) {
                if (input[9] <= 0.5) {
                    if (input[13] <= 2.930999994277954) {
                        var30 = [0.0, 1.0];
                    } else {
                        if (input[0] <= 51.0) {
                            if (input[11] <= 0.5) {
                                var30 = [0.0, 1.0];
                            } else {
                                var30 = [1.0, 0.0];
                            }
                        } else {
                            if (input[1] <= 16.0) {
                                var30 = [0.0, 1.0];
                            } else {
                                var30 = [0.16666666666666666, 0.8333333333333334];
                            }
                        }
                    }
                } else {
                    var30 = [0.0, 1.0];
                }
            } else {
                if (input[6] <= 1.5) {
                    if (input[0] <= 62.5) {
                        if (input[13] <= 3.7839999198913574) {
                            if (input[11] <= 0.5) {
                                var30 = [0.0, 1.0];
                            } else {
                                var30 = [0.8461538461538461, 0.15384615384615385];
                            }
                        } else {
                            var30 = [0.0, 1.0];
                        }
                    } else {
                        var30 = [0.0, 1.0];
                    }
                } else {
                    var30 = [0.0, 1.0];
                }
            }
        } else {
            var30 = [1.0, 0.0];
        }
    }
    var var31;
    if (input[7] <= 0.5) {
        if (input[12] <= 0.5) {
            if (input[1] <= 10.5) {
                if (input[0] <= 35.0) {
                    if (input[6] <= 0.5) {
                        if (input[9] <= 1.0) {
                            if (input[2] <= 2.0) {
                                var31 = [0.8611111111111112, 0.1388888888888889];
                            } else {
                                var31 = [0.0, 1.0];
                            }
                        } else {
                            var31 = [1.0, 0.0];
                        }
                    } else {
                        var31 = [1.0, 0.0];
                    }
                } else {
                    var31 = [0.0, 1.0];
                }
            } else {
                if (input[2] <= 2.5) {
                    if (input[0] <= 36.5) {
                        if (input[2] <= 1.5) {
                            if (input[5] <= 1.5) {
                                var31 = [0.8472222222222222, 0.1527777777777778];
                            } else {
                                var31 = [0.0, 1.0];
                            }
                        } else {
                            if (input[5] <= 2.0) {
                                var31 = [0.9753086419753086, 0.024691358024691357];
                            } else {
                                var31 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[13] <= 3.242500066757202) {
                            if (input[6] <= 0.5) {
                                var31 = [0.23076923076923078, 0.7692307692307693];
                            } else {
                                var31 = [0.5714285714285714, 0.42857142857142855];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var31 = [0.014705882352941176, 0.9852941176470589];
                            } else {
                                var31 = [0.014184397163120567, 0.9858156028368794];
                            }
                        }
                    }
                } else {
                    if (input[1] <= 15.5) {
                        if (input[3] <= 0.5) {
                            var31 = [1.0, 0.0];
                        } else {
                            var31 = [0.0, 1.0];
                        }
                    } else {
                        if (input[4] <= 0.5) {
                            if (input[0] <= 40.0) {
                                var31 = [0.8571428571428571, 0.14285714285714285];
                            } else {
                                var31 = [0.0, 1.0];
                            }
                        } else {
                            var31 = [0.0, 1.0];
                        }
                    }
                }
            }
        } else {
            if (input[1] <= 8.5) {
                var31 = [0.3333333333333333, 0.6666666666666666];
            } else {
                if (input[6] <= 0.5) {
                    if (input[1] <= 9.5) {
                        var31 = [0.058823529411764705, 0.9411764705882353];
                    } else {
                        if (input[0] <= 54.5) {
                            if (input[0] <= 53.0) {
                                var31 = [0.0, 1.0];
                            } else {
                                var31 = [0.125, 0.875];
                            }
                        } else {
                            var31 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[13] <= 3.2330000400543213) {
                        var31 = [0.5, 0.5];
                    } else {
                        if (input[13] <= 3.750499963760376) {
                            if (input[5] <= 0.5) {
                                var31 = [0.07272727272727272, 0.9272727272727272];
                            } else {
                                var31 = [0.5, 0.5];
                            }
                        } else {
                            var31 = [0.0, 1.0];
                        }
                    }
                }
            }
        }
    } else {
        var31 = [1.0, 0.0];
    }
    var var32;
    if (input[7] <= 0.5) {
        if (input[13] <= 2.9049999713897705) {
            if (input[6] <= 0.5) {
                if (input[2] <= 2.0) {
                    if (input[10] <= 0.5) {
                        var32 = [0.9230769230769231, 0.07692307692307693];
                    } else {
                        var32 = [0.0, 1.0];
                    }
                } else {
                    var32 = [0.0, 1.0];
                }
            } else {
                if (input[0] <= 69.0) {
                    var32 = [1.0, 0.0];
                } else {
                    var32 = [0.0, 1.0];
                }
            }
        } else {
            if (input[9] <= 0.5) {
                if (input[5] <= 1.5) {
                    if (input[12] <= 0.5) {
                        if (input[6] <= 0.5) {
                            if (input[2] <= 2.0) {
                                var32 = [0.5172413793103449, 0.4827586206896552];
                            } else {
                                var32 = [0.0, 1.0];
                            }
                        } else {
                            if (input[2] <= 2.5) {
                                var32 = [0.5181347150259067, 0.48186528497409326];
                            } else {
                                var32 = [0.075, 0.925];
                            }
                        }
                    } else {
                        if (input[11] <= 0.5) {
                            var32 = [0.0, 1.0];
                        } else {
                            if (input[13] <= 3.7269999980926514) {
                                var32 = [0.40625, 0.59375];
                            } else {
                                var32 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[1] <= 23.0) {
                        var32 = [0.2, 0.8];
                    } else {
                        var32 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[13] <= 2.9225000143051147) {
                    var32 = [1.0, 0.0];
                } else {
                    if (input[5] <= 0.5) {
                        if (input[11] <= 0.5) {
                            if (input[2] <= 1.5) {
                                var32 = [0.13793103448275862, 0.8620689655172413];
                            } else {
                                var32 = [0.019851116625310174, 0.9801488833746899];
                            }
                        } else {
                            var32 = [0.0, 1.0];
                        }
                    } else {
                        var32 = [0.0, 1.0];
                    }
                }
            }
        }
    } else {
        var32 = [1.0, 0.0];
    }
    var var33;
    if (input[1] <= 11.5) {
        if (input[0] <= 50.5) {
            if (input[11] <= 0.5) {
                if (input[1] <= 8.5) {
                    if (input[0] <= 27.5) {
                        var33 = [1.0, 0.0];
                    } else {
                        if (input[7] <= 0.5) {
                            var33 = [0.25, 0.75];
                        } else {
                            var33 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[2] <= 2.5) {
                        if (input[12] <= 0.5) {
                            if (input[7] <= 0.5) {
                                var33 = [0.7755102040816326, 0.22448979591836735];
                            } else {
                                var33 = [1.0, 0.0];
                            }
                        } else {
                            var33 = [0.0, 1.0];
                        }
                    } else {
                        var33 = [0.0, 1.0];
                    }
                }
            } else {
                var33 = [1.0, 0.0];
            }
        } else {
            var33 = [0.0, 1.0];
        }
    } else {
        if (input[9] <= 0.5) {
            if (input[7] <= 0.5) {
                if (input[3] <= 0.5) {
                    if (input[6] <= 1.5) {
                        if (input[13] <= 3.381500005722046) {
                            if (input[0] <= 54.5) {
                                var33 = [0.8425925925925926, 0.1574074074074074];
                            } else {
                                var33 = [0.0, 1.0];
                            }
                        } else {
                            if (input[5] <= 1.5) {
                                var33 = [0.19615384615384615, 0.8038461538461539];
                            } else {
                                var33 = [0.06451612903225806, 0.9354838709677419];
                            }
                        }
                    } else {
                        if (input[1] <= 18.0) {
                            var33 = [1.0, 0.0];
                        } else {
                            if (input[12] <= 0.5) {
                                var33 = [0.021739130434782608, 0.9782608695652174];
                            } else {
                                var33 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    var33 = [0.0, 1.0];
                }
            } else {
                var33 = [1.0, 0.0];
            }
        } else {
            if (input[10] <= 0.5) {
                if (input[12] <= 0.5) {
                    if (input[13] <= 2.909500002861023) {
                        if (input[0] <= 33.5) {
                            var33 = [1.0, 0.0];
                        } else {
                            if (input[6] <= 0.5) {
                                var33 = [0.0, 1.0];
                            } else {
                                var33 = [0.75, 0.25];
                            }
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            if (input[2] <= 1.5) {
                                var33 = [0.37037037037037035, 0.6296296296296297];
                            } else {
                                var33 = [0.017699115044247787, 0.9823008849557522];
                            }
                        } else {
                            var33 = [1.0, 0.0];
                        }
                    }
                } else {
                    var33 = [0.0, 1.0];
                }
            } else {
                var33 = [0.0, 1.0];
            }
        }
    }
    var var34;
    if (input[0] <= 41.5) {
        if (input[2] <= 2.5) {
            if (input[7] <= 0.5) {
                if (input[10] <= 0.5) {
                    if (input[2] <= 1.5) {
                        if (input[5] <= 1.5) {
                            if (input[12] <= 0.5) {
                                var34 = [0.7569444444444444, 0.24305555555555555];
                            } else {
                                var34 = [0.0, 1.0];
                            }
                        } else {
                            var34 = [0.0, 1.0];
                        }
                    } else {
                        if (input[0] <= 34.5) {
                            var34 = [1.0, 0.0];
                        } else {
                            if (input[11] <= 0.5) {
                                var34 = [0.5, 0.5];
                            } else {
                                var34 = [1.0, 0.0];
                            }
                        }
                    }
                } else {
                    var34 = [0.0, 1.0];
                }
            } else {
                var34 = [1.0, 0.0];
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[0] <= 25.5) {
                    var34 = [1.0, 0.0];
                } else {
                    if (input[6] <= 1.0) {
                        var34 = [0.0, 1.0];
                    } else {
                        var34 = [0.5714285714285714, 0.42857142857142855];
                    }
                }
            } else {
                var34 = [1.0, 0.0];
            }
        }
    } else {
        if (input[7] <= 0.5) {
            if (input[13] <= 3.083999991416931) {
                if (input[1] <= 9.5) {
                    if (input[0] <= 71.0) {
                        var34 = [0.3333333333333333, 0.6666666666666666];
                    } else {
                        var34 = [0.0, 1.0];
                    }
                } else {
                    var34 = [0.0, 1.0];
                }
            } else {
                if (input[1] <= 19.5) {
                    if (input[5] <= 0.5) {
                        if (input[2] <= 1.5) {
                            if (input[13] <= 3.146000027656555) {
                                var34 = [0.4, 0.6];
                            } else {
                                var34 = [0.04411764705882353, 0.9558823529411765];
                            }
                        } else {
                            if (input[2] <= 2.5) {
                                var34 = [0.5, 0.5];
                            } else {
                                var34 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var34 = [0.0, 1.0];
                    }
                } else {
                    if (input[0] <= 59.5) {
                        if (input[0] <= 57.5) {
                            if (input[12] <= 1.5) {
                                var34 = [0.0, 1.0];
                            } else {
                                var34 = [0.15384615384615385, 0.8461538461538461];
                            }
                        } else {
                            if (input[5] <= 0.5) {
                                var34 = [0.6, 0.4];
                            } else {
                                var34 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var34 = [0.0, 1.0];
                    }
                }
            }
        } else {
            var34 = [1.0, 0.0];
        }
    }
    var var35;
    if (input[13] <= 2.909000039100647) {
        if (input[6] <= 0.5) {
            if (input[11] <= 1.5) {
                if (input[13] <= 2.8109999895095825) {
                    if (input[13] <= 2.799499988555908) {
                        if (input[12] <= 0.5) {
                            var35 = [0.215311004784689, 0.784688995215311];
                        } else {
                            if (input[2] <= 2.0) {
                                var35 = [0.22142857142857142, 0.7785714285714286];
                            } else {
                                var35 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var35 = [1.0, 0.0];
                    }
                } else {
                    if (input[2] <= 2.0) {
                        if (input[0] <= 54.5) {
                            if (input[13] <= 2.8639999628067017) {
                                var35 = [1.0, 0.0];
                            } else {
                                var35 = [0.6666666666666666, 0.3333333333333333];
                            }
                        } else {
                            var35 = [0.0, 1.0];
                        }
                    } else {
                        var35 = [0.0, 1.0];
                    }
                }
            } else {
                var35 = [0.0, 1.0];
            }
        } else {
            var35 = [0.9946236559139785, 0.005376344086021506];
        }
    } else {
        if (input[3] <= 0.5) {
            if (input[1] <= 19.5) {
                if (input[7] <= 0.5) {
                    if (input[6] <= 0.5) {
                        if (input[12] <= 0.5) {
                            if (input[1] <= 16.5) {
                                var35 = [0.5555555555555556, 0.4444444444444444];
                            } else {
                                var35 = [0.32, 0.68];
                            }
                        } else {
                            if (input[12] <= 2.5) {
                                var35 = [0.18604651162790697, 0.813953488372093];
                            } else {
                                var35 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[1] <= 18.5) {
                            var35 = [0.8041237113402062, 0.1958762886597938];
                        } else {
                            if (input[0] <= 60.0) {
                                var35 = [0.8333333333333334, 0.16666666666666666];
                            } else {
                                var35 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    var35 = [1.0, 0.0];
                }
            } else {
                if (input[7] <= 0.5) {
                    if (input[0] <= 38.5) {
                        if (input[0] <= 31.5) {
                            var35 = [1.0, 0.0];
                        } else {
                            if (input[5] <= 1.5) {
                                var35 = [0.8, 0.2];
                            } else {
                                var35 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[0] <= 59.5) {
                            if (input[1] <= 23.5) {
                                var35 = [0.16071428571428573, 0.8392857142857143];
                            } else {
                                var35 = [0.0, 1.0];
                            }
                        } else {
                            if (input[5] <= 0.5) {
                                var35 = [0.0, 1.0];
                            } else {
                                var35 = [0.010638297872340425, 0.9893617021276596];
                            }
                        }
                    }
                } else {
                    var35 = [1.0, 0.0];
                }
            }
        } else {
            var35 = [0.0, 1.0];
        }
    }
    var var36;
    if (input[6] <= 0.5) {
        if (input[1] <= 11.5) {
            if (input[11] <= 2.0) {
                if (input[12] <= 0.5) {
                    if (input[3] <= 0.5) {
                        if (input[5] <= 0.5) {
                            if (input[0] <= 48.5) {
                                var36 = [0.9892328398384926, 0.010767160161507403];
                            } else {
                                var36 = [0.0, 1.0];
                            }
                        } else {
                            var36 = [1.0, 0.0];
                        }
                    } else {
                        var36 = [0.0, 1.0];
                    }
                } else {
                    if (input[11] <= 0.5) {
                        var36 = [0.0, 1.0];
                    } else {
                        if (input[13] <= 3.224000096321106) {
                            if (input[7] <= 0.5) {
                                var36 = [0.5, 0.5];
                            } else {
                                var36 = [1.0, 0.0];
                            }
                        } else {
                            var36 = [0.4, 0.6];
                        }
                    }
                }
            } else {
                var36 = [0.0, 1.0];
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[12] <= 0.5) {
                    if (input[2] <= 2.0) {
                        if (input[9] <= 0.5) {
                            if (input[10] <= 0.5) {
                                var36 = [0.5294117647058824, 0.47058823529411764];
                            } else {
                                var36 = [0.0, 1.0];
                            }
                        } else {
                            if (input[9] <= 1.5) {
                                var36 = [0.15789473684210525, 0.8421052631578947];
                            } else {
                                var36 = [0.4, 0.6];
                            }
                        }
                    } else {
                        var36 = [0.0, 1.0];
                    }
                } else {
                    if (input[13] <= 3.009500026702881) {
                        var36 = [0.0, 1.0];
                    } else {
                        if (input[0] <= 48.5) {
                            var36 = [0.6666666666666666, 0.3333333333333333];
                        } else {
                            if (input[11] <= 0.5) {
                                var36 = [0.0, 1.0];
                            } else {
                                var36 = [0.018867924528301886, 0.9811320754716981];
                            }
                        }
                    }
                }
            } else {
                var36 = [1.0, 0.0];
            }
        }
    } else {
        if (input[13] <= 3.6829999685287476) {
            if (input[9] <= 0.5) {
                if (input[13] <= 3.3834999799728394) {
                    if (input[6] <= 1.5) {
                        if (input[0] <= 62.5) {
                            if (input[5] <= 0.5) {
                                var36 = [0.9965714285714286, 0.0034285714285714284];
                            } else {
                                var36 = [0.9333333333333333, 0.06666666666666667];
                            }
                        } else {
                            var36 = [0.0, 1.0];
                        }
                    } else {
                        var36 = [1.0, 0.0];
                    }
                } else {
                    if (input[1] <= 19.5) {
                        if (input[0] <= 62.0) {
                            if (input[7] <= 0.5) {
                                var36 = [0.88, 0.12];
                            } else {
                                var36 = [1.0, 0.0];
                            }
                        } else {
                            var36 = [0.0, 1.0];
                        }
                    } else {
                        if (input[13] <= 3.603999972343445) {
                            if (input[7] <= 0.5) {
                                var36 = [0.05263157894736842, 0.9473684210526315];
                            } else {
                                var36 = [1.0, 0.0];
                            }
                        } else {
                            if (input[0] <= 50.5) {
                                var36 = [0.9482758620689655, 0.05172413793103448];
                            } else {
                                var36 = [0.46153846153846156, 0.5384615384615384];
                            }
                        }
                    }
                }
            } else {
                if (input[0] <= 52.0) {
                    var36 = [1.0, 0.0];
                } else {
                    var36 = [0.0, 1.0];
                }
            }
        } else {
            if (input[1] <= 19.5) {
                if (input[0] <= 45.0) {
                    var36 = [1.0, 0.0];
                } else {
                    if (input[0] <= 65.5) {
                        if (input[12] <= 1.5) {
                            if (input[12] <= 0.5) {
                                var36 = [0.5, 0.5];
                            } else {
                                var36 = [0.0, 1.0];
                            }
                        } else {
                            var36 = [1.0, 0.0];
                        }
                    } else {
                        var36 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[7] <= 0.5) {
                    if (input[12] <= 0.5) {
                        if (input[1] <= 20.5) {
                            var36 = [0.0, 1.0];
                        } else {
                            var36 = [0.10091743119266056, 0.8990825688073395];
                        }
                    } else {
                        if (input[12] <= 2.5) {
                            if (input[13] <= 3.756999969482422) {
                                var36 = [0.16666666666666666, 0.8333333333333334];
                            } else {
                                var36 = [0.0, 1.0];
                            }
                        } else {
                            var36 = [0.0, 1.0];
                        }
                    }
                } else {
                    var36 = [1.0, 0.0];
                }
            }
        }
    }
    var var37;
    if (input[7] <= 0.5) {
        if (input[0] <= 29.5) {
            if (input[6] <= 0.5) {
                if (input[5] <= 0.5) {
                    var37 = [0.7676767676767676, 0.23232323232323232];
                } else {
                    var37 = [1.0, 0.0];
                }
            } else {
                if (input[0] <= 27.5) {
                    var37 = [1.0, 0.0];
                } else {
                    if (input[1] <= 14.5) {
                        var37 = [0.75, 0.25];
                    } else {
                        var37 = [1.0, 0.0];
                    }
                }
            }
        } else {
            if (input[3] <= 0.5) {
                if (input[1] <= 19.5) {
                    if (input[6] <= 0.5) {
                        if (input[10] <= 0.5) {
                            if (input[1] <= 9.5) {
                                var37 = [0.35714285714285715, 0.6428571428571429];
                            } else {
                                var37 = [0.14285714285714285, 0.8571428571428571];
                            }
                        } else {
                            var37 = [0.0, 1.0];
                        }
                    } else {
                        if (input[4] <= 0.5) {
                            if (input[13] <= 3.245500087738037) {
                                var37 = [0.8333333333333334, 0.16666666666666666];
                            } else {
                                var37 = [0.5555555555555556, 0.4444444444444444];
                            }
                        } else {
                            var37 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[1] <= 26.5) {
                        if (input[2] <= 1.5) {
                            if (input[10] <= 0.5) {
                                var37 = [0.4, 0.6];
                            } else {
                                var37 = [0.0, 1.0];
                            }
                        } else {
                            if (input[13] <= 3.7335000038146973) {
                                var37 = [0.018223234624145785, 0.9817767653758542];
                            } else {
                                var37 = [0.1388888888888889, 0.8611111111111112];
                            }
                        }
                    } else {
                        if (input[0] <= 39.0) {
                            var37 = [0.25, 0.75];
                        } else {
                            var37 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var37 = [0.0, 1.0];
            }
        }
    } else {
        var37 = [1.0, 0.0];
    }
    var var38;
    if (input[7] <= 0.5) {
        if (input[13] <= 2.909000039100647) {
            if (input[13] <= 1.6100000143051147) {
                var38 = [0.6666666666666666, 0.3333333333333333];
            } else {
                if (input[6] <= 0.5) {
                    if (input[2] <= 2.0) {
                        if (input[0] <= 39.0) {
                            if (input[0] <= 20.5) {
                                var38 = [1.0, 0.0];
                            } else {
                                var38 = [0.8888888888888888, 0.1111111111111111];
                            }
                        } else {
                            var38 = [0.0, 1.0];
                        }
                    } else {
                        var38 = [0.0, 1.0];
                    }
                } else {
                    if (input[13] <= 2.653499960899353) {
                        if (input[12] <= 3.5) {
                            var38 = [0.5, 0.5];
                        } else {
                            var38 = [0.0, 1.0];
                        }
                    } else {
                        var38 = [1.0, 0.0];
                    }
                }
            }
        } else {
            if (input[1] <= 19.5) {
                if (input[6] <= 0.5) {
                    if (input[3] <= 0.5) {
                        if (input[0] <= 33.5) {
                            if (input[0] <= 23.5) {
                                var38 = [1.0, 0.0];
                            } else {
                                var38 = [0.75, 0.25];
                            }
                        } else {
                            if (input[1] <= 13.5) {
                                var38 = [0.2463768115942029, 0.7536231884057971];
                            } else {
                                var38 = [0.04411764705882353, 0.9558823529411765];
                            }
                        }
                    } else {
                        var38 = [0.0, 1.0];
                    }
                } else {
                    if (input[0] <= 60.5) {
                        if (input[2] <= 2.5) {
                            if (input[13] <= 3.5110000371932983) {
                                var38 = [1.0, 0.0];
                            } else {
                                var38 = [0.5555555555555556, 0.4444444444444444];
                            }
                        } else {
                            var38 = [1.0, 0.0];
                        }
                    } else {
                        var38 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[9] <= 0.5) {
                    if (input[1] <= 26.5) {
                        if (input[1] <= 20.5) {
                            if (input[6] <= 0.5) {
                                var38 = [1.0, 0.0];
                            } else {
                                var38 = [0.025, 0.975];
                            }
                        } else {
                            if (input[2] <= 2.5) {
                                var38 = [0.3076923076923077, 0.6923076923076923];
                            } else {
                                var38 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[1] <= 30.5) {
                            if (input[11] <= 0.5) {
                                var38 = [0.04, 0.96];
                            } else {
                                var38 = [0.0, 1.0];
                            }
                        } else {
                            var38 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[6] <= 0.5) {
                        if (input[0] <= 44.0) {
                            var38 = [1.0, 0.0];
                        } else {
                            var38 = [0.0, 1.0];
                        }
                    } else {
                        if (input[1] <= 20.5) {
                            var38 = [0.0, 1.0];
                        } else {
                            if (input[9] <= 1.5) {
                                var38 = [0.06060606060606061, 0.9393939393939394];
                            } else {
                                var38 = [0.0, 1.0];
                            }
                        }
                    }
                }
            }
        }
    } else {
        var38 = [1.0, 0.0];
    }
    var var39;
    if (input[7] <= 0.5) {
        if (input[1] <= 10.5) {
            if (input[12] <= 0.5) {
                if (input[13] <= 2.6134999990463257) {
                    if (input[0] <= 27.5) {
                        var39 = [1.0, 0.0];
                    } else {
                        var39 = [0.5, 0.5];
                    }
                } else {
                    if (input[0] <= 29.5) {
                        if (input[0] <= 25.5) {
                            if (input[6] <= 0.5) {
                                var39 = [0.9375, 0.0625];
                            } else {
                                var39 = [1.0, 0.0];
                            }
                        } else {
                            var39 = [0.75, 0.25];
                        }
                    } else {
                        if (input[13] <= 2.934999942779541) {
                            var39 = [0.2, 0.8];
                        } else {
                            var39 = [0.6666666666666666, 0.3333333333333333];
                        }
                    }
                }
            } else {
                if (input[1] <= 8.5) {
                    var39 = [0.0, 1.0];
                } else {
                    if (input[0] <= 49.0) {
                        var39 = [0.6, 0.4];
                    } else {
                        var39 = [0.0, 1.0];
                    }
                }
            }
        } else {
            if (input[0] <= 29.5) {
                if (input[3] <= 0.5) {
                    var39 = [0.9537037037037037, 0.046296296296296294];
                } else {
                    var39 = [0.0, 1.0];
                }
            } else {
                if (input[13] <= 3.177999973297119) {
                    if (input[3] <= 0.5) {
                        if (input[0] <= 38.0) {
                            if (input[13] <= 2.916000008583069) {
                                var39 = [1.0, 0.0];
                            } else {
                                var39 = [0.5454545454545454, 0.45454545454545453];
                            }
                        } else {
                            if (input[1] <= 12.5) {
                                var39 = [0.125, 0.875];
                            } else {
                                var39 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var39 = [0.0, 1.0];
                    }
                } else {
                    if (input[9] <= 0.5) {
                        if (input[12] <= 2.5) {
                            if (input[4] <= 0.5) {
                                var39 = [0.1341772151898734, 0.8658227848101265];
                            } else {
                                var39 = [0.0, 1.0];
                            }
                        } else {
                            var39 = [0.0, 1.0];
                        }
                    } else {
                        if (input[1] <= 19.5) {
                            if (input[6] <= 0.5) {
                                var39 = [0.06666666666666667, 0.9333333333333333];
                            } else {
                                var39 = [1.0, 0.0];
                            }
                        } else {
                            if (input[2] <= 2.5) {
                                var39 = [0.0070921985815602835, 0.9929078014184397];
                            } else {
                                var39 = [0.10526315789473684, 0.8947368421052632];
                            }
                        }
                    }
                }
            }
        }
    } else {
        var39 = [1.0, 0.0];
    }
    var var40;
    if (input[7] <= 0.5) {
        if (input[6] <= 0.5) {
            if (input[3] <= 0.5) {
                if (input[10] <= 0.5) {
                    if (input[9] <= 0.5) {
                        if (input[0] <= 33.5) {
                            if (input[13] <= 2.9394999742507935) {
                                var40 = [0.7692307692307693, 0.23076923076923078];
                            } else {
                                var40 = [0.9411764705882353, 0.058823529411764705];
                            }
                        } else {
                            if (input[1] <= 8.5) {
                                var40 = [0.3333333333333333, 0.6666666666666666];
                            } else {
                                var40 = [0.12962962962962962, 0.8703703703703703];
                            }
                        }
                    } else {
                        if (input[1] <= 7.5) {
                            var40 = [1.0, 0.0];
                        } else {
                            if (input[13] <= 3.559000015258789) {
                                var40 = [0.06521739130434782, 0.9347826086956522];
                            } else {
                                var40 = [0.4166666666666667, 0.5833333333333334];
                            }
                        }
                    }
                } else {
                    var40 = [0.0, 1.0];
                }
            } else {
                var40 = [0.0, 1.0];
            }
        } else {
            if (input[2] <= 2.5) {
                if (input[0] <= 36.5) {
                    if (input[13] <= 3.8030000925064087) {
                        if (input[0] <= 27.5) {
                            var40 = [1.0, 0.0];
                        } else {
                            if (input[0] <= 28.5) {
                                var40 = [0.7777777777777778, 0.2222222222222222];
                            } else {
                                var40 = [0.96875, 0.03125];
                            }
                        }
                    } else {
                        var40 = [0.4444444444444444, 0.5555555555555556];
                    }
                } else {
                    if (input[0] <= 58.5) {
                        if (input[0] <= 47.5) {
                            if (input[12] <= 1.5) {
                                var40 = [0.17142857142857143, 0.8285714285714286];
                            } else {
                                var40 = [0.6666666666666666, 0.3333333333333333];
                            }
                        } else {
                            if (input[0] <= 48.5) {
                                var40 = [0.75, 0.25];
                            } else {
                                var40 = [0.3611111111111111, 0.6388888888888888];
                            }
                        }
                    } else {
                        if (input[5] <= 0.5) {
                            var40 = [0.0, 1.0];
                        } else {
                            if (input[11] <= 0.5) {
                                var40 = [0.0, 1.0];
                            } else {
                                var40 = [0.16666666666666666, 0.8333333333333334];
                            }
                        }
                    }
                }
            } else {
                if (input[6] <= 2.5) {
                    if (input[0] <= 40.0) {
                        var40 = [1.0, 0.0];
                    } else {
                        var40 = [0.0, 1.0];
                    }
                } else {
                    var40 = [0.0, 1.0];
                }
            }
        }
    } else {
        var40 = [1.0, 0.0];
    }
    var var41;
    if (input[9] <= 0.5) {
        if (input[7] <= 0.5) {
            if (input[2] <= 2.5) {
                if (input[1] <= 19.5) {
                    if (input[2] <= 1.5) {
                        if (input[5] <= 1.5) {
                            if (input[11] <= 2.0) {
                                var41 = [0.5476190476190477, 0.4523809523809524];
                            } else {
                                var41 = [0.0, 1.0];
                            }
                        } else {
                            var41 = [0.0, 1.0];
                        }
                    } else {
                        if (input[12] <= 2.5) {
                            if (input[10] <= 0.5) {
                                var41 = [0.897196261682243, 0.102803738317757];
                            } else {
                                var41 = [0.3333333333333333, 0.6666666666666666];
                            }
                        } else {
                            var41 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[6] <= 0.5) {
                        if (input[5] <= 0.5) {
                            if (input[12] <= 1.0) {
                                var41 = [0.2, 0.8];
                            } else {
                                var41 = [0.0, 1.0];
                            }
                        } else {
                            if (input[13] <= 3.533500075340271) {
                                var41 = [1.0, 0.0];
                            } else {
                                var41 = [0.16666666666666666, 0.8333333333333334];
                            }
                        }
                    } else {
                        var41 = [0.11555555555555555, 0.8844444444444445];
                    }
                }
            } else {
                if (input[5] <= 0.5) {
                    if (input[1] <= 14.5) {
                        if (input[13] <= 2.801500082015991) {
                            var41 = [0.0, 1.0];
                        } else {
                            var41 = [0.002304147465437788, 0.9976958525345622];
                        }
                    } else {
                        if (input[3] <= 0.5) {
                            if (input[2] <= 3.5) {
                                var41 = [0.0375, 0.9625];
                            } else {
                                var41 = [0.0, 1.0];
                            }
                        } else {
                            var41 = [0.0, 1.0];
                        }
                    }
                } else {
                    var41 = [0.0, 1.0];
                }
            }
        } else {
            var41 = [1.0, 0.0];
        }
    } else {
        if (input[2] <= 2.5) {
            if (input[1] <= 19.5) {
                if (input[10] <= 0.5) {
                    if (input[6] <= 0.5) {
                        if (input[12] <= 0.5) {
                            if (input[7] <= 0.5) {
                                var41 = [0.34375, 0.65625];
                            } else {
                                var41 = [1.0, 0.0];
                            }
                        } else {
                            var41 = [0.0, 1.0];
                        }
                    } else {
                        var41 = [1.0, 0.0];
                    }
                } else {
                    var41 = [0.0, 1.0];
                }
            } else {
                if (input[12] <= 0.5) {
                    if (input[7] <= 0.5) {
                        if (input[6] <= 0.5) {
                            if (input[13] <= 3.621999979019165) {
                                var41 = [0.0, 1.0];
                            } else {
                                var41 = [0.25, 0.75];
                            }
                        } else {
                            var41 = [0.0, 1.0];
                        }
                    } else {
                        var41 = [1.0, 0.0];
                    }
                } else {
                    var41 = [0.0, 1.0];
                }
            }
        } else {
            if (input[6] <= 1.0) {
                var41 = [0.0, 1.0];
            } else {
                if (input[1] <= 23.5) {
                    var41 = [1.0, 0.0];
                } else {
                    var41 = [0.0, 1.0];
                }
            }
        }
    }
    var var42;
    if (input[10] <= 0.5) {
        if (input[3] <= 0.5) {
            if (input[6] <= 0.5) {
                if (input[1] <= 20.5) {
                    if (input[9] <= 2.5) {
                        if (input[0] <= 51.5) {
                            if (input[5] <= 1.5) {
                                var42 = [0.9719923615531508, 0.028007638446849142];
                            } else {
                                var42 = [0.3333333333333333, 0.6666666666666666];
                            }
                        } else {
                            if (input[1] <= 13.5) {
                                var42 = [0.0, 1.0];
                            } else {
                                var42 = [0.3157894736842105, 0.6842105263157895];
                            }
                        }
                    } else {
                        var42 = [0.0, 1.0];
                    }
                } else {
                    if (input[9] <= 0.5) {
                        if (input[13] <= 3.573499917984009) {
                            var42 = [1.0, 0.0];
                        } else {
                            if (input[7] <= 0.5) {
                                var42 = [0.05263157894736842, 0.9473684210526315];
                            } else {
                                var42 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[1] <= 21.5) {
                            var42 = [0.3333333333333333, 0.6666666666666666];
                        } else {
                            var42 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                if (input[7] <= 0.5) {
                    if (input[13] <= 3.3830000162124634) {
                        if (input[9] <= 0.5) {
                            if (input[13] <= 3.243000030517578) {
                                var42 = [0.9791666666666666, 0.020833333333333332];
                            } else {
                                var42 = [0.575, 0.425];
                            }
                        } else {
                            if (input[1] <= 19.5) {
                                var42 = [1.0, 0.0];
                            } else {
                                var42 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[13] <= 3.540500044822693) {
                            if (input[9] <= 0.5) {
                                var42 = [0.38461538461538464, 0.6153846153846154];
                            } else {
                                var42 = [0.057692307692307696, 0.9423076923076923];
                            }
                        } else {
                            if (input[0] <= 34.5) {
                                var42 = [0.875, 0.125];
                            } else {
                                var42 = [0.02631578947368421, 0.9736842105263158];
                            }
                        }
                    }
                } else {
                    var42 = [1.0, 0.0];
                }
            }
        } else {
            var42 = [0.0, 1.0];
        }
    } else {
        if (input[0] <= 36.0) {
            var42 = [0.5, 0.5];
        } else {
            if (input[0] <= 48.5) {
                if (input[13] <= 3.50600004196167) {
                    var42 = [0.0, 1.0];
                } else {
                    var42 = [0.5, 0.5];
                }
            } else {
                var42 = [0.0, 1.0];
            }
        }
    }
    var var43;
    if (input[7] <= 0.5) {
        if (input[2] <= 2.5) {
            if (input[1] <= 19.5) {
                if (input[11] <= 1.5) {
                    if (input[2] <= 1.5) {
                        if (input[13] <= 2.728500008583069) {
                            if (input[0] <= 20.5) {
                                var43 = [1.0, 0.0];
                            } else {
                                var43 = [0.8888888888888888, 0.1111111111111111];
                            }
                        } else {
                            if (input[0] <= 36.5) {
                                var43 = [0.85, 0.15];
                            } else {
                                var43 = [0.14545454545454545, 0.8545454545454545];
                            }
                        }
                    } else {
                        if (input[1] <= 11.5) {
                            if (input[13] <= 3.021999955177307) {
                                var43 = [1.0, 0.0];
                            } else {
                                var43 = [0.5, 0.5];
                            }
                        } else {
                            if (input[10] <= 0.5) {
                                var43 = [0.7476635514018691, 0.2523364485981308];
                            } else {
                                var43 = [0.3333333333333333, 0.6666666666666666];
                            }
                        }
                    }
                } else {
                    var43 = [0.0, 1.0];
                }
            } else {
                if (input[1] <= 20.5) {
                    if (input[13] <= 3.365000009536743) {
                        if (input[13] <= 3.2649999856948853) {
                            var43 = [0.0, 1.0];
                        } else {
                            if (input[11] <= 0.5) {
                                var43 = [0.5, 0.5];
                            } else {
                                var43 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            var43 = [0.0379746835443038, 0.9620253164556962];
                        } else {
                            if (input[11] <= 0.5) {
                                var43 = [0.003134796238244514, 0.9968652037617555];
                            } else {
                                var43 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[12] <= 0.5) {
                        if (input[6] <= 0.5) {
                            if (input[9] <= 0.5) {
                                var43 = [0.16666666666666666, 0.8333333333333334];
                            } else {
                                var43 = [0.18181818181818182, 0.8181818181818182];
                            }
                        } else {
                            if (input[0] <= 36.5) {
                                var43 = [0.8695652173913043, 0.13043478260869565];
                            } else {
                                var43 = [0.1896551724137931, 0.8103448275862069];
                            }
                        }
                    } else {
                        if (input[10] <= 0.5) {
                            if (input[13] <= 3.4915000200271606) {
                                var43 = [0.25, 0.75];
                            } else {
                                var43 = [0.0, 1.0];
                            }
                        } else {
                            var43 = [0.0, 1.0];
                        }
                    }
                }
            }
        } else {
            if (input[0] <= 26.5) {
                var43 = [1.0, 0.0];
            } else {
                if (input[1] <= 18.5) {
                    if (input[6] <= 1.0) {
                        var43 = [0.0, 1.0];
                    } else {
                        var43 = [0.5, 0.5];
                    }
                } else {
                    if (input[13] <= 3.587999939918518) {
                        if (input[0] <= 45.0) {
                            var43 = [1.0, 0.0];
                        } else {
                            var43 = [0.0, 1.0];
                        }
                    } else {
                        if (input[0] <= 38.5) {
                            var43 = [0.2857142857142857, 0.7142857142857143];
                        } else {
                            var43 = [0.0, 1.0];
                        }
                    }
                }
            }
        }
    } else {
        var43 = [1.0, 0.0];
    }
    var var44;
    if (input[0] <= 40.5) {
        if (input[2] <= 2.5) {
            if (input[7] <= 0.5) {
                if (input[0] <= 33.5) {
                    if (input[5] <= 0.5) {
                        if (input[6] <= 0.5) {
                            if (input[9] <= 0.5) {
                                var44 = [0.8953488372093024, 0.10465116279069768];
                            } else {
                                var44 = [0.7272727272727273, 0.2727272727272727];
                            }
                        } else {
                            var44 = [1.0, 0.0];
                        }
                    } else {
                        var44 = [1.0, 0.0];
                    }
                } else {
                    if (input[9] <= 1.5) {
                        if (input[0] <= 38.5) {
                            if (input[1] <= 11.5) {
                                var44 = [0.875, 0.125];
                            } else {
                                var44 = [0.32, 0.68];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var44 = [0.16666666666666666, 0.8333333333333334];
                            } else {
                                var44 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var44 = [0.6666666666666666, 0.3333333333333333];
                    }
                }
            } else {
                var44 = [1.0, 0.0];
            }
        } else {
            if (input[2] <= 4.0) {
                if (input[3] <= 0.5) {
                    if (input[9] <= 0.5) {
                        if (input[13] <= 3.91949999332428) {
                            var44 = [1.0, 0.0];
                        } else {
                            var44 = [0.5, 0.5];
                        }
                    } else {
                        var44 = [1.0, 0.0];
                    }
                } else {
                    var44 = [0.0, 1.0];
                }
            } else {
                var44 = [1.0, 0.0];
            }
        }
    } else {
        if (input[1] <= 10.5) {
            if (input[12] <= 1.5) {
                var44 = [0.4888888888888889, 0.5111111111111111];
            } else {
                if (input[13] <= 3.0609999895095825) {
                    if (input[6] <= 0.5) {
                        if (input[1] <= 8.5) {
                            if (input[13] <= 2.6675000190734863) {
                                var44 = [1.0, 0.0];
                            } else {
                                var44 = [0.9166666666666666, 0.08333333333333333];
                            }
                        } else {
                            var44 = [1.0, 0.0];
                        }
                    } else {
                        var44 = [1.0, 0.0];
                    }
                } else {
                    if (input[0] <= 47.5) {
                        var44 = [1.0, 0.0];
                    } else {
                        var44 = [0.5, 0.5];
                    }
                }
            }
        } else {
            if (input[1] <= 15.5) {
                if (input[2] <= 2.5) {
                    if (input[7] <= 0.5) {
                        if (input[1] <= 12.5) {
                            if (input[11] <= 0.5) {
                                var44 = [0.0, 1.0];
                            } else {
                                var44 = [0.4, 0.6];
                            }
                        } else {
                            if (input[13] <= 3.424999952316284) {
                                var44 = [0.3684210526315789, 0.631578947368421];
                            } else {
                                var44 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var44 = [1.0, 0.0];
                    }
                } else {
                    if (input[6] <= 1.0) {
                        var44 = [0.0, 1.0];
                    } else {
                        var44 = [1.0, 0.0];
                    }
                }
            } else {
                if (input[0] <= 59.5) {
                    if (input[7] <= 0.5) {
                        if (input[6] <= 1.5) {
                            if (input[10] <= 0.5) {
                                var44 = [0.2553191489361702, 0.7446808510638298];
                            } else {
                                var44 = [0.0, 1.0];
                            }
                        } else {
                            var44 = [0.0, 1.0];
                        }
                    } else {
                        var44 = [1.0, 0.0];
                    }
                } else {
                    if (input[13] <= 3.6514999866485596) {
                        var44 = [0.0, 1.0];
                    } else {
                        if (input[1] <= 21.5) {
                            var44 = [0.0, 1.0];
                        } else {
                            if (input[6] <= 1.5) {
                                var44 = [0.05, 0.95];
                            } else {
                                var44 = [0.0, 1.0];
                            }
                        }
                    }
                }
            }
        }
    }
    var var45;
    if (input[13] <= 2.909000039100647) {
        if (input[2] <= 2.5) {
            if (input[13] <= 2.2345000505447388) {
                if (input[0] <= 50.5) {
                    var45 = [1.0, 0.0];
                } else {
                    var45 = [0.0, 1.0];
                }
            } else {
                if (input[9] <= 0.5) {
                    if (input[2] <= 1.5) {
                        if (input[1] <= 13.5) {
                            if (input[7] <= 0.5) {
                                var45 = [0.8387096774193549, 0.16129032258064516];
                            } else {
                                var45 = [1.0, 0.0];
                            }
                        } else {
                            var45 = [0.5, 0.5];
                        }
                    } else {
                        var45 = [1.0, 0.0];
                    }
                } else {
                    if (input[13] <= 2.471500039100647) {
                        if (input[1] <= 17.5) {
                            var45 = [1.0, 0.0];
                        } else {
                            var45 = [0.0, 1.0];
                        }
                    } else {
                        if (input[1] <= 21.0) {
                            var45 = [1.0, 0.0];
                        } else {
                            var45 = [0.0, 1.0];
                        }
                    }
                }
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[0] <= 26.5) {
                    var45 = [0.5, 0.5];
                } else {
                    var45 = [0.0, 1.0];
                }
            } else {
                var45 = [1.0, 0.0];
            }
        }
    } else {
        if (input[13] <= 3.6829999685287476) {
            if (input[3] <= 0.5) {
                if (input[10] <= 0.5) {
                    if (input[7] <= 0.5) {
                        if (input[0] <= 36.5) {
                            if (input[2] <= 1.5) {
                                var45 = [0.8441558441558441, 0.15584415584415584];
                            } else {
                                var45 = [1.0, 0.0];
                            }
                        } else {
                            if (input[1] <= 19.5) {
                                var45 = [0.21764705882352942, 0.7823529411764706];
                            } else {
                                var45 = [0.04830917874396135, 0.9516908212560387];
                            }
                        }
                    } else {
                        var45 = [1.0, 0.0];
                    }
                } else {
                    var45 = [0.0, 1.0];
                }
            } else {
                var45 = [0.0, 1.0];
            }
        } else {
            if (input[1] <= 19.5) {
                if (input[0] <= 44.5) {
                    var45 = [1.0, 0.0];
                } else {
                    if (input[0] <= 50.5) {
                        if (input[13] <= 3.723499894142151) {
                            var45 = [0.5, 0.5];
                        } else {
                            var45 = [0.5, 0.5];
                        }
                    } else {
                        var45 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[0] <= 58.5) {
                    if (input[2] <= 2.5) {
                        if (input[1] <= 23.5) {
                            if (input[12] <= 1.0) {
                                var45 = [0.898876404494382, 0.10112359550561797];
                            } else {
                                var45 = [1.0, 0.0];
                            }
                        } else {
                            if (input[12] <= 0.5) {
                                var45 = [0.6190476190476191, 0.38095238095238093];
                            } else {
                                var45 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[1] <= 22.5) {
                                var45 = [1.0, 0.0];
                            } else {
                                var45 = [0.21428571428571427, 0.7857142857142857];
                            }
                        } else {
                            var45 = [0.6666666666666666, 0.3333333333333333];
                        }
                    }
                } else {
                    if (input[5] <= 0.5) {
                        if (input[2] <= 2.5) {
                            if (input[0] <= 64.5) {
                                var45 = [0.25, 0.75];
                            } else {
                                var45 = [0.0, 1.0];
                            }
                        } else {
                            var45 = [0.0, 1.0];
                        }
                    } else {
                        if (input[6] <= 2.5) {
                            var45 = [0.0, 1.0];
                        } else {
                            if (input[9] <= 1.0) {
                                var45 = [0.3333333333333333, 0.6666666666666666];
                            } else {
                                var45 = [0.0, 1.0];
                            }
                        }
                    }
                }
            }
        }
    }
    var var46;
    if (input[13] <= 2.909000039100647) {
        if (input[7] <= 0.5) {
            if (input[1] <= 9.5) {
                if (input[2] <= 1.5) {
                    if (input[0] <= 35.0) {
                        if (input[1] <= 7.5) {
                            var46 = [1.0, 0.0];
                        } else {
                            var46 = [0.5, 0.5];
                        }
                    } else {
                        var46 = [0.0, 1.0];
                    }
                } else {
                    var46 = [1.0, 0.0];
                }
            } else {
                if (input[12] <= 2.5) {
                    if (input[13] <= 2.843500018119812) {
                        if (input[6] <= 0.5) {
                            if (input[2] <= 2.0) {
                                var46 = [0.0423728813559322, 0.9576271186440678];
                            } else {
                                var46 = [0.0, 1.0];
                            }
                        } else {
                            if (input[9] <= 0.5) {
                                var46 = [1.0, 0.0];
                            } else {
                                var46 = [0.6666666666666666, 0.3333333333333333];
                            }
                        }
                    } else {
                        if (input[12] <= 0.5) {
                            if (input[0] <= 38.5) {
                                var46 = [0.22580645161290322, 0.7741935483870968];
                            } else {
                                var46 = [0.0, 1.0];
                            }
                        } else {
                            var46 = [0.0, 1.0];
                        }
                    }
                } else {
                    var46 = [0.0, 1.0];
                }
            }
        } else {
            var46 = [1.0, 0.0];
        }
    } else {
        if (input[0] <= 48.5) {
            if (input[7] <= 0.5) {
                if (input[3] <= 0.5) {
                    if (input[10] <= 0.5) {
                        if (input[0] <= 36.5) {
                            if (input[13] <= 2.9199999570846558) {
                                var46 = [0.42857142857142855, 0.5714285714285714];
                            } else {
                                var46 = [0.9166666666666666, 0.08333333333333333];
                            }
                        } else {
                            if (input[13] <= 3.773500084877014) {
                                var46 = [0.33783783783783783, 0.6621621621621622];
                            } else {
                                var46 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var46 = [0.0, 1.0];
                    }
                } else {
                    var46 = [0.0, 1.0];
                }
            } else {
                var46 = [1.0, 0.0];
            }
        } else {
            if (input[0] <= 59.5) {
                if (input[7] <= 0.5) {
                    if (input[0] <= 58.5) {
                        if (input[1] <= 16.5) {
                            var46 = [0.0, 1.0];
                        } else {
                            if (input[2] <= 1.5) {
                                var46 = [0.0, 1.0];
                            } else {
                                var46 = [0.1111111111111111, 0.8888888888888888];
                            }
                        }
                    } else {
                        var46 = [0.6666666666666666, 0.3333333333333333];
                    }
                } else {
                    var46 = [1.0, 0.0];
                }
            } else {
                if (input[0] <= 61.5) {
                    if (input[1] <= 27.0) {
                        if (input[13] <= 3.620500087738037) {
                            var46 = [0.0, 1.0];
                        } else {
                            var46 = [0.6666666666666666, 0.3333333333333333];
                        }
                    } else {
                        var46 = [0.0, 1.0];
                    }
                } else {
                    if (input[3] <= 0.5) {
                        if (input[11] <= 0.5) {
                            if (input[10] <= 0.5) {
                                var46 = [0.004158004158004158, 0.9958419958419958];
                            } else {
                                var46 = [0.0, 1.0];
                            }
                        } else {
                            var46 = [0.0, 1.0];
                        }
                    } else {
                        var46 = [0.0, 1.0];
                    }
                }
            }
        }
    }
    var var47;
    if (input[12] <= 2.5) {
        if (input[0] <= 40.5) {
            if (input[3] <= 0.5) {
                if (input[6] <= 0.5) {
                    if (input[5] <= 1.5) {
                        if (input[5] <= 0.5) {
                            if (input[0] <= 30.5) {
                                var47 = [0.9929718875502008, 0.007028112449799197];
                            } else {
                                var47 = [0.9198606271777003, 0.08013937282229965];
                            }
                        } else {
                            var47 = [1.0, 0.0];
                        }
                    } else {
                        if (input[13] <= 3.7335000038146973) {
                            var47 = [0.75, 0.25];
                        } else {
                            var47 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[13] <= 3.853500008583069) {
                        if (input[1] <= 25.5) {
                            if (input[1] <= 13.5) {
                                var47 = [1.0, 0.0];
                            } else {
                                var47 = [0.9876819708846585, 0.012318029115341545];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var47 = [0.14285714285714285, 0.8571428571428571];
                            } else {
                                var47 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[13] <= 3.8765000104904175) {
                            var47 = [0.0, 1.0];
                        } else {
                            if (input[0] <= 32.5) {
                                var47 = [1.0, 0.0];
                            } else {
                                var47 = [0.6470588235294118, 0.35294117647058826];
                            }
                        }
                    }
                }
            } else {
                var47 = [0.0, 1.0];
            }
        } else {
            if (input[13] <= 2.9049999713897705) {
                if (input[11] <= 0.5) {
                    if (input[3] <= 0.5) {
                        if (input[13] <= 2.7410000562667847) {
                            if (input[1] <= 10.0) {
                                var47 = [1.0, 0.0];
                            } else {
                                var47 = [0.0078125, 0.9921875];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var47 = [0.0, 1.0];
                            } else {
                                var47 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var47 = [0.0, 1.0];
                    }
                } else {
                    if (input[13] <= 2.8109999895095825) {
                        if (input[2] <= 2.5) {
                            var47 = [1.0, 0.0];
                        } else {
                            var47 = [0.0, 1.0];
                        }
                    } else {
                        if (input[3] <= 0.5) {
                            var47 = [1.0, 0.0];
                        } else {
                            var47 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                if (input[0] <= 59.5) {
                    if (input[2] <= 2.5) {
                        if (input[0] <= 47.5) {
                            if (input[7] <= 0.5) {
                                var47 = [0.16666666666666666, 0.8333333333333334];
                            } else {
                                var47 = [1.0, 0.0];
                            }
                        } else {
                            if (input[11] <= 0.5) {
                                var47 = [0.28846153846153844, 0.7115384615384616];
                            } else {
                                var47 = [0.975609756097561, 0.024390243902439025];
                            }
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            var47 = [0.0, 1.0];
                        } else {
                            var47 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[11] <= 0.5) {
                        if (input[0] <= 62.5) {
                            if (input[13] <= 3.6360000371932983) {
                                var47 = [0.0, 1.0];
                            } else {
                                var47 = [0.29411764705882354, 0.7058823529411765];
                            }
                        } else {
                            var47 = [0.0, 1.0];
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            if (input[5] <= 0.5) {
                                var47 = [0.0, 1.0];
                            } else {
                                var47 = [0.3333333333333333, 0.6666666666666666];
                            }
                        } else {
                            var47 = [1.0, 0.0];
                        }
                    }
                }
            }
        }
    } else {
        var47 = [0.0, 1.0];
    }
    var var48;
    if (input[13] <= 2.909000039100647) {
        if (input[12] <= 2.5) {
            if (input[1] <= 11.5) {
                if (input[0] <= 47.5) {
                    if (input[1] <= 10.5) {
                        if (input[9] <= 1.5) {
                            if (input[1] <= 9.5) {
                                var48 = [1.0, 0.0];
                            } else {
                                var48 = [0.9285714285714286, 0.07142857142857142];
                            }
                        } else {
                            if (input[13] <= 2.5820000171661377) {
                                var48 = [1.0, 0.0];
                            } else {
                                var48 = [0.875, 0.125];
                            }
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            var48 = [0.2777777777777778, 0.7222222222222222];
                        } else {
                            var48 = [1.0, 0.0];
                        }
                    }
                } else {
                    var48 = [0.041666666666666664, 0.9583333333333334];
                }
            } else {
                if (input[7] <= 0.5) {
                    if (input[2] <= 2.5) {
                        if (input[9] <= 0.5) {
                            var48 = [0.75, 0.25];
                        } else {
                            var48 = [0.0, 1.0];
                        }
                    } else {
                        var48 = [0.0, 1.0];
                    }
                } else {
                    var48 = [1.0, 0.0];
                }
            }
        } else {
            var48 = [0.0, 1.0];
        }
    } else {
        if (input[9] <= 0.5) {
            if (input[13] <= 3.791000008583069) {
                if (input[12] <= 2.5) {
                    if (input[7] <= 0.5) {
                        if (input[2] <= 2.5) {
                            if (input[12] <= 0.5) {
                                var48 = [0.5441176470588235, 0.45588235294117646];
                            } else {
                                var48 = [0.1566265060240964, 0.8433734939759037];
                            }
                        } else {
                            if (input[1] <= 15.5) {
                                var48 = [0.006134969325153374, 0.9938650306748467];
                            } else {
                                var48 = [0.23076923076923078, 0.7692307692307693];
                            }
                        }
                    } else {
                        var48 = [1.0, 0.0];
                    }
                } else {
                    var48 = [0.0, 1.0];
                }
            } else {
                if (input[2] <= 2.5) {
                    if (input[6] <= 0.5) {
                        if (input[13] <= 3.812000036239624) {
                            var48 = [0.0, 1.0];
                        } else {
                            var48 = [1.0, 0.0];
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            if (input[1] <= 22.0) {
                                var48 = [0.3076923076923077, 0.6923076923076923];
                            } else {
                                var48 = [0.02564102564102564, 0.9743589743589743];
                            }
                        } else {
                            var48 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[6] <= 2.5) {
                        var48 = [0.0, 1.0];
                    } else {
                        if (input[6] <= 4.0) {
                            var48 = [0.3333333333333333, 0.6666666666666666];
                        } else {
                            var48 = [0.0, 1.0];
                        }
                    }
                }
            }
        } else {
            if (input[13] <= 3.6829999685287476) {
                if (input[6] <= 0.5) {
                    if (input[10] <= 0.5) {
                        if (input[13] <= 3.0674999952316284) {
                            if (input[9] <= 2.5) {
                                var48 = [0.16091954022988506, 0.8390804597701149];
                            } else {
                                var48 = [0.0, 1.0];
                            }
                        } else {
                            if (input[5] <= 0.5) {
                                var48 = [0.7294117647058823, 0.27058823529411763];
                            } else {
                                var48 = [0.13636363636363635, 0.8636363636363636];
                            }
                        }
                    } else {
                        var48 = [0.0, 1.0];
                    }
                } else {
                    if (input[1] <= 19.5) {
                        var48 = [1.0, 0.0];
                    } else {
                        if (input[13] <= 3.6155000925064087) {
                            if (input[2] <= 2.5) {
                                var48 = [0.12222222222222222, 0.8777777777777778];
                            } else {
                                var48 = [1.0, 0.0];
                            }
                        } else {
                            var48 = [1.0, 0.0];
                        }
                    }
                }
            } else {
                if (input[9] <= 1.5) {
                    if (input[2] <= 4.5) {
                        if (input[7] <= 0.5) {
                            if (input[13] <= 3.794000029563904) {
                                var48 = [0.2222222222222222, 0.7777777777777778];
                            } else {
                                var48 = [0.0, 1.0];
                            }
                        } else {
                            var48 = [1.0, 0.0];
                        }
                    } else {
                        var48 = [0.0, 1.0];
                    }
                } else {
                    if (input[0] <= 74.5) {
                        var48 = [0.3333333333333333, 0.6666666666666666];
                    } else {
                        var48 = [0.0, 1.0];
                    }
                }
            }
        }
    }
    var var49;
    if (input[9] <= 0.5) {
        if (input[1] <= 11.5) {
            if (input[2] <= 2.5) {
                if (input[13] <= 3.146000027656555) {
                    if (input[1] <= 7.5) {
                        var49 = [1.0, 0.0];
                    } else {
                        if (input[7] <= 0.5) {
                            if (input[13] <= 2.934999942779541) {
                                var49 = [0.59375, 0.40625];
                            } else {
                                var49 = [0.8148148148148148, 0.18518518518518517];
                            }
                        } else {
                            var49 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[0] <= 50.5) {
                        if (input[0] <= 23.0) {
                            var49 = [1.0, 0.0];
                        } else {
                            var49 = [0.9692307692307692, 0.03076923076923077];
                        }
                    } else {
                        var49 = [0.0, 1.0];
                    }
                }
            } else {
                var49 = [0.0, 1.0];
            }
        } else {
            if (input[1] <= 15.5) {
                if (input[3] <= 0.5) {
                    if (input[11] <= 4.5) {
                        if (input[0] <= 54.0) {
                            if (input[2] <= 1.5) {
                                var49 = [0.9523809523809523, 0.047619047619047616];
                            } else {
                                var49 = [0.9980842911877394, 0.0019157088122605363];
                            }
                        } else {
                            var49 = [0.0, 1.0];
                        }
                    } else {
                        var49 = [0.0, 1.0];
                    }
                } else {
                    var49 = [0.0, 1.0];
                }
            } else {
                if (input[7] <= 0.5) {
                    if (input[1] <= 19.5) {
                        if (input[5] <= 0.5) {
                            if (input[11] <= 1.5) {
                                var49 = [0.7671232876712328, 0.2328767123287671];
                            } else {
                                var49 = [0.0, 1.0];
                            }
                        } else {
                            var49 = [0.0, 1.0];
                        }
                    } else {
                        if (input[2] <= 1.5) {
                            if (input[1] <= 29.0) {
                                var49 = [0.6, 0.4];
                            } else {
                                var49 = [0.0, 1.0];
                            }
                        } else {
                            if (input[0] <= 33.5) {
                                var49 = [1.0, 0.0];
                            } else {
                                var49 = [0.040229885057471264, 0.9597701149425287];
                            }
                        }
                    }
                } else {
                    var49 = [1.0, 0.0];
                }
            }
        }
    } else {
        if (input[0] <= 41.5) {
            if (input[7] <= 0.5) {
                if (input[2] <= 2.5) {
                    if (input[9] <= 1.5) {
                        if (input[13] <= 3.263000011444092) {
                            if (input[13] <= 2.8035000562667847) {
                                var49 = [1.0, 0.0];
                            } else {
                                var49 = [0.6666666666666666, 0.3333333333333333];
                            }
                        } else {
                            if (input[10] <= 0.5) {
                                var49 = [0.25, 0.75];
                            } else {
                                var49 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[6] <= 0.5) {
                            var49 = [0.75, 0.25];
                        } else {
                            var49 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[6] <= 1.0) {
                        var49 = [0.0, 1.0];
                    } else {
                        var49 = [1.0, 0.0];
                    }
                }
            } else {
                var49 = [1.0, 0.0];
            }
        } else {
            if (input[0] <= 43.5) {
                if (input[3] <= 0.5) {
                    if (input[6] <= 0.5) {
                        var49 = [0.6666666666666666, 0.3333333333333333];
                    } else {
                        var49 = [1.0, 0.0];
                    }
                } else {
                    var49 = [0.0, 1.0];
                }
            } else {
                if (input[7] <= 0.5) {
                    var49 = [0.0, 1.0];
                } else {
                    var49 = [1.0, 0.0];
                }
            }
        }
    }
    var var50;
    if (input[7] <= 0.5) {
        if (input[0] <= 28.5) {
            if (input[9] <= 0.5) {
                if (input[2] <= 2.5) {
                    if (input[0] <= 27.5) {
                        if (input[13] <= 3.1725000143051147) {
                            if (input[6] <= 0.5) {
                                var50 = [0.8888888888888888, 0.1111111111111111];
                            } else {
                                var50 = [1.0, 0.0];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var50 = [0.9629629629629629, 0.037037037037037035];
                            } else {
                                var50 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[1] <= 12.5) {
                            var50 = [0.0, 1.0];
                        } else {
                            var50 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[13] <= 2.801500082015991) {
                        var50 = [0.0, 1.0];
                    } else {
                        var50 = [0.6666666666666666, 0.3333333333333333];
                    }
                }
            } else {
                var50 = [1.0, 0.0];
            }
        } else {
            if (input[6] <= 0.5) {
                if (input[2] <= 2.0) {
                    if (input[12] <= 0.5) {
                        if (input[13] <= 3.100000023841858) {
                            if (input[9] <= 0.5) {
                                var50 = [0.5, 0.5];
                            } else {
                                var50 = [0.14285714285714285, 0.8571428571428571];
                            }
                        } else {
                            if (input[1] <= 22.5) {
                                var50 = [0.22388059701492538, 0.7761194029850746];
                            } else {
                                var50 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[13] <= 2.712999939918518) {
                            var50 = [0.0, 1.0];
                        } else {
                            if (input[1] <= 13.5) {
                                var50 = [0.21951219512195122, 0.7804878048780488];
                            } else {
                                var50 = [0.022556390977443608, 0.9774436090225563];
                            }
                        }
                    }
                } else {
                    var50 = [0.0, 1.0];
                }
            } else {
                if (input[0] <= 42.0) {
                    if (input[0] <= 35.5) {
                        if (input[1] <= 22.5) {
                            var50 = [1.0, 0.0];
                        } else {
                            var50 = [0.6666666666666666, 0.3333333333333333];
                        }
                    } else {
                        var50 = [0.42857142857142855, 0.5714285714285714];
                    }
                } else {
                    if (input[0] <= 59.5) {
                        if (input[6] <= 1.5) {
                            if (input[13] <= 3.3954999446868896) {
                                var50 = [0.7142857142857143, 0.2857142857142857];
                            } else {
                                var50 = [0.15384615384615385, 0.8461538461538461];
                            }
                        } else {
                            var50 = [0.0, 1.0];
                        }
                    } else {
                        var50 = [0.0, 1.0];
                    }
                }
            }
        }
    } else {
        var50 = [1.0, 0.0];
    }
    var var51;
    if (input[0] <= 40.5) {
        if (input[13] <= 2.9049999713897705) {
            if (input[0] <= 28.5) {
                if (input[1] <= 13.5) {
                    var51 = [1.0, 0.0];
                } else {
                    if (input[0] <= 25.5) {
                        var51 = [1.0, 0.0];
                    } else {
                        var51 = [0.3333333333333333, 0.6666666666666666];
                    }
                }
            } else {
                if (input[3] <= 0.5) {
                    if (input[7] <= 0.5) {
                        if (input[13] <= 2.8600000143051147) {
                            if (input[0] <= 30.5) {
                                var51 = [1.0, 0.0];
                            } else {
                                var51 = [0.8, 0.2];
                            }
                        } else {
                            var51 = [0.25, 0.75];
                        }
                    } else {
                        var51 = [1.0, 0.0];
                    }
                } else {
                    var51 = [0.0, 1.0];
                }
            }
        } else {
            if (input[10] <= 0.5) {
                if (input[2] <= 2.5) {
                    if (input[5] <= 1.5) {
                        if (input[12] <= 0.5) {
                            if (input[9] <= 0.5) {
                                var51 = [0.9851052901900359, 0.014894709809964048];
                            } else {
                                var51 = [0.9942528735632183, 0.005747126436781609];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var51 = [0.9090909090909091, 0.09090909090909091];
                            } else {
                                var51 = [0.3333333333333333, 0.6666666666666666];
                            }
                        }
                    } else {
                        if (input[5] <= 2.5) {
                            if (input[0] <= 36.5) {
                                var51 = [0.0, 1.0];
                            } else {
                                var51 = [1.0, 0.0];
                            }
                        } else {
                            var51 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[3] <= 0.5) {
                        if (input[13] <= 3.91949999332428) {
                            var51 = [1.0, 0.0];
                        } else {
                            var51 = [0.5, 0.5];
                        }
                    } else {
                        var51 = [0.0, 1.0];
                    }
                }
            } else {
                var51 = [0.5, 0.5];
            }
        }
    } else {
        if (input[7] <= 0.5) {
            if (input[3] <= 0.5) {
                if (input[12] <= 1.5) {
                    if (input[0] <= 43.5) {
                        if (input[10] <= 0.5) {
                            if (input[1] <= 15.5) {
                                var51 = [1.0, 0.0];
                            } else {
                                var51 = [0.0, 1.0];
                            }
                        } else {
                            var51 = [0.0, 1.0];
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[4] <= 0.5) {
                                var51 = [0.003861003861003861, 0.9961389961389961];
                            } else {
                                var51 = [0.0, 1.0];
                            }
                        } else {
                            var51 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[0] <= 57.5) {
                        if (input[0] <= 43.5) {
                            var51 = [0.2, 0.8];
                        } else {
                            if (input[9] <= 0.5) {
                                var51 = [0.8571428571428571, 0.14285714285714285];
                            } else {
                                var51 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[0] <= 58.5) {
                            var51 = [0.13043478260869565, 0.8695652173913043];
                        } else {
                            if (input[9] <= 0.5) {
                                var51 = [0.007692307692307693, 0.9923076923076923];
                            } else {
                                var51 = [0.0, 1.0];
                            }
                        }
                    }
                }
            } else {
                var51 = [0.0, 1.0];
            }
        } else {
            var51 = [1.0, 0.0];
        }
    }
    var var52;
    if (input[3] <= 0.5) {
        if (input[7] <= 0.5) {
            if (input[9] <= 0.5) {
                if (input[12] <= 0.5) {
                    if (input[13] <= 3.40749990940094) {
                        if (input[2] <= 1.5) {
                            if (input[0] <= 30.5) {
                                var52 = [0.9420289855072463, 0.057971014492753624];
                            } else {
                                var52 = [0.3541666666666667, 0.6458333333333334];
                            }
                        } else {
                            if (input[5] <= 0.5) {
                                var52 = [0.9420289855072463, 0.057971014492753624];
                            } else {
                                var52 = [0.5, 0.5];
                            }
                        }
                    } else {
                        var52 = [0.2578125, 0.7421875];
                    }
                } else {
                    if (input[0] <= 59.5) {
                        if (input[11] <= 0.5) {
                            var52 = [0.0, 1.0];
                        } else {
                            if (input[2] <= 1.5) {
                                var52 = [1.0, 0.0];
                            } else {
                                var52 = [0.7333333333333333, 0.26666666666666666];
                            }
                        }
                    } else {
                        var52 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[5] <= 0.5) {
                    if (input[0] <= 39.5) {
                        if (input[6] <= 0.5) {
                            var52 = [0.7777777777777778, 0.2222222222222222];
                        } else {
                            var52 = [1.0, 0.0];
                        }
                    } else {
                        var52 = [0.0, 1.0];
                    }
                } else {
                    var52 = [0.0, 1.0];
                }
            }
        } else {
            var52 = [1.0, 0.0];
        }
    } else {
        var52 = [0.0, 1.0];
    }
    var var53;
    if (input[3] <= 0.5) {
        if (input[0] <= 57.5) {
            if (input[1] <= 19.5) {
                if (input[7] <= 0.5) {
                    if (input[6] <= 0.5) {
                        if (input[9] <= 0.5) {
                            if (input[13] <= 2.9049999713897705) {
                                var53 = [0.9512195121951219, 0.04878048780487805];
                            } else {
                                var53 = [0.4768211920529801, 0.5231788079470199];
                            }
                        } else {
                            if (input[0] <= 30.5) {
                                var53 = [1.0, 0.0];
                            } else {
                                var53 = [0.06666666666666667, 0.9333333333333333];
                            }
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[12] <= 0.5) {
                                var53 = [0.9196428571428571, 0.08035714285714286];
                            } else {
                                var53 = [0.75, 0.25];
                            }
                        } else {
                            var53 = [1.0, 0.0];
                        }
                    }
                } else {
                    var53 = [1.0, 0.0];
                }
            } else {
                if (input[7] <= 0.5) {
                    if (input[0] <= 33.5) {
                        var53 = [1.0, 0.0];
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[13] <= 3.531000018119812) {
                                var53 = [0.4666666666666667, 0.5333333333333333];
                            } else {
                                var53 = [0.14473684210526316, 0.8552631578947368];
                            }
                        } else {
                            var53 = [0.0, 1.0];
                        }
                    }
                } else {
                    var53 = [1.0, 0.0];
                }
            }
        } else {
            if (input[0] <= 60.5) {
                if (input[11] <= 0.5) {
                    if (input[13] <= 3.6125000715255737) {
                        var53 = [0.0, 1.0];
                    } else {
                        if (input[13] <= 3.8485000133514404) {
                            if (input[1] <= 21.5) {
                                var53 = [0.5, 0.5];
                            } else {
                                var53 = [1.0, 0.0];
                            }
                        } else {
                            var53 = [0.0, 1.0];
                        }
                    }
                } else {
                    var53 = [1.0, 0.0];
                }
            } else {
                if (input[13] <= 3.6514999866485596) {
                    var53 = [0.0, 1.0];
                } else {
                    if (input[10] <= 0.5) {
                        if (input[13] <= 3.6829999685287476) {
                            if (input[11] <= 0.5) {
                                var53 = [0.2857142857142857, 0.7142857142857143];
                            } else {
                                var53 = [0.0, 1.0];
                            }
                        } else {
                            if (input[0] <= 61.5) {
                                var53 = [0.25, 0.75];
                            } else {
                                var53 = [0.0022123893805309734, 0.9977876106194691];
                            }
                        }
                    } else {
                        var53 = [0.0, 1.0];
                    }
                }
            }
        }
    } else {
        var53 = [0.0, 1.0];
    }
    var var54;
    if (input[0] <= 40.5) {
        if (input[5] <= 2.5) {
            if (input[0] <= 29.5) {
                if (input[0] <= 28.5) {
                    if (input[2] <= 2.5) {
                        var54 = [0.9946714031971581, 0.0053285968028419185];
                    } else {
                        if (input[6] <= 1.0) {
                            var54 = [0.0, 1.0];
                        } else {
                            var54 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[13] <= 2.8300000429153442) {
                        var54 = [0.0, 1.0];
                    } else {
                        if (input[1] <= 16.5) {
                            if (input[7] <= 0.5) {
                                var54 = [0.625, 0.375];
                            } else {
                                var54 = [1.0, 0.0];
                            }
                        } else {
                            var54 = [1.0, 0.0];
                        }
                    }
                }
            } else {
                if (input[13] <= 2.916000008583069) {
                    if (input[7] <= 0.5) {
                        if (input[13] <= 2.843500018119812) {
                            if (input[9] <= 0.5) {
                                var54 = [0.0035335689045936395, 0.9964664310954063];
                            } else {
                                var54 = [0.0, 1.0];
                            }
                        } else {
                            if (input[0] <= 32.5) {
                                var54 = [0.0, 1.0];
                            } else {
                                var54 = [0.15789473684210525, 0.8421052631578947];
                            }
                        }
                    } else {
                        var54 = [1.0, 0.0];
                    }
                } else {
                    if (input[6] <= 0.5) {
                        if (input[13] <= 3.058500051498413) {
                            if (input[3] <= 0.5) {
                                var54 = [0.8333333333333334, 0.16666666666666666];
                            } else {
                                var54 = [0.0, 1.0];
                            }
                        } else {
                            var54 = [0.8995633187772926, 0.10043668122270742];
                        }
                    } else {
                        if (input[0] <= 39.5) {
                            if (input[1] <= 26.5) {
                                var54 = [0.9867256637168141, 0.01327433628318584];
                            } else {
                                var54 = [0.92, 0.08];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var54 = [0.2222222222222222, 0.7777777777777778];
                            } else {
                                var54 = [1.0, 0.0];
                            }
                        }
                    }
                }
            }
        } else {
            var54 = [0.0, 1.0];
        }
    } else {
        if (input[7] <= 0.5) {
            if (input[12] <= 1.5) {
                if (input[0] <= 41.5) {
                    if (input[3] <= 0.5) {
                        var54 = [0.4444444444444444, 0.5555555555555556];
                    } else {
                        var54 = [0.0, 1.0];
                    }
                } else {
                    if (input[13] <= 3.3274999856948853) {
                        var54 = [0.0, 1.0];
                    } else {
                        if (input[13] <= 3.3615000247955322) {
                            var54 = [0.5, 0.5];
                        } else {
                            if (input[0] <= 43.5) {
                                var54 = [0.5, 0.5];
                            } else {
                                var54 = [0.0035587188612099642, 0.99644128113879];
                            }
                        }
                    }
                }
            } else {
                if (input[9] <= 0.5) {
                    if (input[0] <= 58.5) {
                        if (input[11] <= 0.5) {
                            var54 = [0.0, 1.0];
                        } else {
                            var54 = [0.7948717948717948, 0.20512820512820512];
                        }
                    } else {
                        if (input[3] <= 0.5) {
                            if (input[0] <= 61.5) {
                                var54 = [0.5, 0.5];
                            } else {
                                var54 = [0.0, 1.0];
                            }
                        } else {
                            var54 = [0.0, 1.0];
                        }
                    }
                } else {
                    var54 = [0.0, 1.0];
                }
            }
        } else {
            var54 = [1.0, 0.0];
        }
    }
    var var55;
    if (input[1] <= 11.5) {
        if (input[3] <= 0.5) {
            if (input[12] <= 0.5) {
                if (input[13] <= 2.6134999990463257) {
                    var55 = [1.0, 0.0];
                } else {
                    if (input[7] <= 0.5) {
                        if (input[1] <= 9.5) {
                            if (input[13] <= 2.6834999322891235) {
                                var55 = [0.75, 0.25];
                            } else {
                                var55 = [0.92, 0.08];
                            }
                        } else {
                            if (input[9] <= 0.5) {
                                var55 = [0.7666666666666667, 0.23333333333333334];
                            } else {
                                var55 = [0.8666666666666667, 0.13333333333333333];
                            }
                        }
                    } else {
                        var55 = [1.0, 0.0];
                    }
                }
            } else {
                if (input[9] <= 0.5) {
                    if (input[11] <= 0.5) {
                        var55 = [0.0, 1.0];
                    } else {
                        var55 = [1.0, 0.0];
                    }
                } else {
                    var55 = [0.0, 1.0];
                }
            }
        } else {
            var55 = [0.0, 1.0];
        }
    } else {
        if (input[0] <= 38.5) {
            if (input[3] <= 0.5) {
                if (input[11] <= 0.5) {
                    if (input[13] <= 3.808000087738037) {
                        if (input[6] <= 0.5) {
                            if (input[9] <= 1.5) {
                                var55 = [0.9514018691588785, 0.048598130841121495];
                            } else {
                                var55 = [1.0, 0.0];
                            }
                        } else {
                            if (input[1] <= 25.5) {
                                var55 = [0.9982363315696648, 0.001763668430335097];
                            } else {
                                var55 = [0.9166666666666666, 0.08333333333333333];
                            }
                        }
                    } else {
                        if (input[5] <= 2.5) {
                            if (input[5] <= 0.5) {
                                var55 = [0.8387096774193549, 0.16129032258064516];
                            } else {
                                var55 = [1.0, 0.0];
                            }
                        } else {
                            var55 = [0.0, 1.0];
                        }
                    }
                } else {
                    var55 = [0.0, 1.0];
                }
            } else {
                var55 = [0.0, 1.0];
            }
        } else {
            if (input[3] <= 0.5) {
                if (input[7] <= 0.5) {
                    if (input[1] <= 19.5) {
                        if (input[12] <= 2.5) {
                            if (input[6] <= 0.5) {
                                var55 = [0.0, 1.0];
                            } else {
                                var55 = [0.5384615384615384, 0.46153846153846156];
                            }
                        } else {
                            var55 = [0.0, 1.0];
                        }
                    } else {
                        if (input[11] <= 0.5) {
                            if (input[0] <= 62.5) {
                                var55 = [0.02040816326530612, 0.9795918367346939];
                            } else {
                                var55 = [0.0, 1.0];
                            }
                        } else {
                            if (input[13] <= 3.3125) {
                                var55 = [0.3, 0.7];
                            } else {
                                var55 = [0.016260162601626018, 0.983739837398374];
                            }
                        }
                    }
                } else {
                    var55 = [1.0, 0.0];
                }
            } else {
                var55 = [0.0, 1.0];
            }
        }
    }
    var var56;
    if (input[0] <= 41.5) {
        if (input[3] <= 0.5) {
            if (input[0] <= 33.5) {
                if (input[0] <= 25.5) {
                    var56 = [1.0, 0.0];
                } else {
                    if (input[5] <= 0.5) {
                        if (input[6] <= 0.5) {
                            if (input[1] <= 14.5) {
                                var56 = [0.9491525423728814, 0.05084745762711865];
                            } else {
                                var56 = [0.9915254237288136, 0.00847457627118644];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var56 = [0.96875, 0.03125];
                            } else {
                                var56 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var56 = [1.0, 0.0];
                    }
                }
            } else {
                if (input[7] <= 0.5) {
                    if (input[0] <= 40.5) {
                        if (input[13] <= 3.325500011444092) {
                            if (input[13] <= 2.9765000343322754) {
                                var56 = [0.16666666666666666, 0.8333333333333334];
                            } else {
                                var56 = [1.0, 0.0];
                            }
                        } else {
                            if (input[5] <= 1.5) {
                                var56 = [0.23529411764705882, 0.7647058823529411];
                            } else {
                                var56 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[2] <= 1.5) {
                            var56 = [0.6666666666666666, 0.3333333333333333];
                        } else {
                            var56 = [1.0, 0.0];
                        }
                    }
                } else {
                    var56 = [1.0, 0.0];
                }
            }
        } else {
            var56 = [0.0, 1.0];
        }
    } else {
        if (input[6] <= 0.5) {
            if (input[1] <= 10.5) {
                var56 = [0.625, 0.375];
            } else {
                if (input[11] <= 0.5) {
                    if (input[0] <= 42.5) {
                        if (input[13] <= 3.180999994277954) {
                            var56 = [0.0, 1.0];
                        } else {
                            var56 = [1.0, 0.0];
                        }
                    } else {
                        if (input[12] <= 0.5) {
                            if (input[0] <= 55.5) {
                                var56 = [0.05272727272727273, 0.9472727272727273];
                            } else {
                                var56 = [0.0, 1.0];
                            }
                        } else {
                            var56 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[2] <= 2.0) {
                        if (input[0] <= 61.0) {
                            var56 = [1.0, 0.0];
                        } else {
                            var56 = [0.0, 1.0];
                        }
                    } else {
                        var56 = [0.0, 1.0];
                    }
                }
            }
        } else {
            if (input[11] <= 0.5) {
                if (input[9] <= 0.5) {
                    if (input[13] <= 3.242500066757202) {
                        var56 = [0.9736842105263158, 0.02631578947368421];
                    } else {
                        if (input[7] <= 0.5) {
                            if (input[0] <= 59.5) {
                                var56 = [0.04054054054054054, 0.9594594594594594];
                            } else {
                                var56 = [0.0, 1.0];
                            }
                        } else {
                            var56 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[7] <= 0.5) {
                        var56 = [0.0, 1.0];
                    } else {
                        var56 = [1.0, 0.0];
                    }
                }
            } else {
                if (input[0] <= 70.0) {
                    if (input[2] <= 2.5) {
                        if (input[1] <= 22.5) {
                            var56 = [1.0, 0.0];
                        } else {
                            if (input[13] <= 3.6410000324249268) {
                                var56 = [0.6666666666666666, 0.3333333333333333];
                            } else {
                                var56 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var56 = [1.0, 0.0];
                    }
                } else {
                    var56 = [0.0, 1.0];
                }
            }
        }
    }
    var var57;
    if (input[3] <= 0.5) {
        if (input[0] <= 57.5) {
            if (input[5] <= 1.5) {
                if (input[6] <= 2.5) {
                    if (input[7] <= 0.5) {
                        if (input[0] <= 38.5) {
                            if (input[11] <= 0.5) {
                                var57 = [0.8681318681318682, 0.13186813186813187];
                            } else {
                                var57 = [0.0, 1.0];
                            }
                        } else {
                            if (input[0] <= 50.5) {
                                var57 = [0.34065934065934067, 0.6593406593406593];
                            } else {
                                var57 = [0.05, 0.95];
                            }
                        }
                    } else {
                        var57 = [1.0, 0.0];
                    }
                } else {
                    if (input[1] <= 23.0) {
                        var57 = [0.0, 1.0];
                    } else {
                        if (input[6] <= 3.5) {
                            var57 = [0.0, 1.0];
                        } else {
                            var57 = [1.0, 0.0];
                        }
                    }
                }
            } else {
                if (input[6] <= 1.5) {
                    if (input[7] <= 0.5) {
                        var57 = [0.041666666666666664, 0.9583333333333334];
                    } else {
                        var57 = [1.0, 0.0];
                    }
                } else {
                    var57 = [0.0, 1.0];
                }
            }
        } else {
            if (input[9] <= 0.5) {
                if (input[0] <= 63.0) {
                    if (input[12] <= 1.0) {
                        if (input[6] <= 0.5) {
                            var57 = [1.0, 0.0];
                        } else {
                            if (input[13] <= 3.624000072479248) {
                                var57 = [0.08333333333333333, 0.9166666666666666];
                            } else {
                                var57 = [0.7, 0.3];
                            }
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            var57 = [0.5, 0.5];
                        } else {
                            var57 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[0] <= 67.5) {
                        if (input[2] <= 3.5) {
                            var57 = [0.0, 1.0];
                        } else {
                            var57 = [0.75, 0.25];
                        }
                    } else {
                        var57 = [0.0, 1.0];
                    }
                }
            } else {
                var57 = [0.0, 1.0];
            }
        }
    } else {
        var57 = [0.0, 1.0];
    }
    var var58;
    if (input[0] <= 41.5) {
        if (input[7] <= 0.5) {
            if (input[13] <= 2.9049999713897705) {
                if (input[2] <= 2.5) {
                    if (input[0] <= 26.5) {
                        var58 = [1.0, 0.0];
                    } else {
                        var58 = [0.6666666666666666, 0.3333333333333333];
                    }
                } else {
                    if (input[1] <= 13.5) {
                        var58 = [0.017241379310344827, 0.9827586206896551];
                    } else {
                        var58 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[2] <= 2.5) {
                    if (input[0] <= 33.5) {
                        if (input[13] <= 2.9394999742507935) {
                            if (input[9] <= 1.0) {
                                var58 = [0.5384615384615384, 0.46153846153846156];
                            } else {
                                var58 = [1.0, 0.0];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var58 = [0.9122807017543859, 0.08771929824561403];
                            } else {
                                var58 = [0.9722222222222222, 0.027777777777777776];
                            }
                        }
                    } else {
                        if (input[13] <= 3.309000015258789) {
                            if (input[1] <= 15.5) {
                                var58 = [0.7619047619047619, 0.23809523809523808];
                            } else {
                                var58 = [0.3333333333333333, 0.6666666666666666];
                            }
                        } else {
                            if (input[9] <= 0.5) {
                                var58 = [0.23076923076923078, 0.7692307692307693];
                            } else {
                                var58 = [1.0, 0.0];
                            }
                        }
                    }
                } else {
                    if (input[13] <= 3.1959999799728394) {
                        var58 = [0.0, 1.0];
                    } else {
                        var58 = [0.5, 0.5];
                    }
                }
            }
        } else {
            var58 = [1.0, 0.0];
        }
    } else {
        if (input[1] <= 10.5) {
            var58 = [0.6923076923076923, 0.3076923076923077];
        } else {
            if (input[13] <= 3.041499972343445) {
                if (input[6] <= 0.5) {
                    if (input[2] <= 2.0) {
                        if (input[11] <= 0.5) {
                            if (input[10] <= 0.5) {
                                var58 = [0.09090909090909091, 0.9090909090909091];
                            } else {
                                var58 = [0.0, 1.0];
                            }
                        } else {
                            if (input[1] <= 13.0) {
                                var58 = [1.0, 0.0];
                            } else {
                                var58 = [0.3333333333333333, 0.6666666666666666];
                            }
                        }
                    } else {
                        var58 = [0.0, 1.0];
                    }
                } else {
                    if (input[1] <= 17.0) {
                        var58 = [1.0, 0.0];
                    } else {
                        var58 = [0.5, 0.5];
                    }
                }
            } else {
                if (input[2] <= 1.5) {
                    if (input[1] <= 23.5) {
                        if (input[0] <= 60.0) {
                            if (input[7] <= 0.5) {
                                var58 = [0.23529411764705882, 0.7647058823529411];
                            } else {
                                var58 = [1.0, 0.0];
                            }
                        } else {
                            var58 = [0.0, 1.0];
                        }
                    } else {
                        if (input[1] <= 27.5) {
                            if (input[0] <= 53.0) {
                                var58 = [0.2, 0.8];
                            } else {
                                var58 = [0.0, 1.0];
                            }
                        } else {
                            var58 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[11] <= 0.5) {
                        if (input[7] <= 0.5) {
                            if (input[2] <= 2.5) {
                                var58 = [0.010183299389002037, 0.9898167006109979];
                            } else {
                                var58 = [0.0, 1.0];
                            }
                        } else {
                            var58 = [1.0, 0.0];
                        }
                    } else {
                        if (input[13] <= 3.7269999980926514) {
                            if (input[7] <= 0.5) {
                                var58 = [0.13333333333333333, 0.8666666666666667];
                            } else {
                                var58 = [1.0, 0.0];
                            }
                        } else {
                            if (input[0] <= 71.5) {
                                var58 = [1.0, 0.0];
                            } else {
                                var58 = [0.0, 1.0];
                            }
                        }
                    }
                }
            }
        }
    }
    var var59;
    if (input[3] <= 0.5) {
        if (input[7] <= 0.5) {
            if (input[0] <= 33.5) {
                if (input[6] <= 0.5) {
                    if (input[13] <= 2.9394999742507935) {
                        if (input[1] <= 12.5) {
                            if (input[13] <= 2.881500005722046) {
                                var59 = [0.9354838709677419, 0.06451612903225806];
                            } else {
                                var59 = [0.25, 0.75];
                            }
                        } else {
                            var59 = [0.0, 1.0];
                        }
                    } else {
                        if (input[13] <= 3.146000027656555) {
                            var59 = [1.0, 0.0];
                        } else {
                            var59 = [0.9459459459459459, 0.05405405405405406];
                        }
                    }
                } else {
                    if (input[6] <= 1.5) {
                        if (input[0] <= 31.5) {
                            var59 = [1.0, 0.0];
                        } else {
                            var59 = [0.9375, 0.0625];
                        }
                    } else {
                        if (input[0] <= 31.5) {
                            var59 = [1.0, 0.0];
                        } else {
                            var59 = [0.6, 0.4];
                        }
                    }
                }
            } else {
                if (input[0] <= 44.5) {
                    if (input[9] <= 0.5) {
                        if (input[5] <= 2.5) {
                            if (input[12] <= 0.5) {
                                var59 = [0.45, 0.55];
                            } else {
                                var59 = [0.23076923076923078, 0.7692307692307693];
                            }
                        } else {
                            var59 = [0.0, 1.0];
                        }
                    } else {
                        if (input[5] <= 1.0) {
                            if (input[0] <= 38.0) {
                                var59 = [1.0, 0.0];
                            } else {
                                var59 = [0.16666666666666666, 0.8333333333333334];
                            }
                        } else {
                            var59 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[0] <= 62.5) {
                        if (input[11] <= 0.5) {
                            if (input[13] <= 3.7165000438690186) {
                                var59 = [0.0, 1.0];
                            } else {
                                var59 = [0.03333333333333333, 0.9666666666666667];
                            }
                        } else {
                            if (input[10] <= 0.5) {
                                var59 = [0.8260869565217391, 0.17391304347826086];
                            } else {
                                var59 = [0.3333333333333333, 0.6666666666666666];
                            }
                        }
                    } else {
                        var59 = [0.0, 1.0];
                    }
                }
            }
        } else {
            var59 = [1.0, 0.0];
        }
    } else {
        var59 = [0.0, 1.0];
    }
    var var60;
    if (input[12] <= 2.5) {
        if (input[0] <= 41.5) {
            if (input[3] <= 0.5) {
                if (input[0] <= 35.5) {
                    if (input[10] <= 0.5) {
                        if (input[7] <= 0.5) {
                            if (input[0] <= 30.5) {
                                var60 = [0.9655172413793104, 0.034482758620689655];
                            } else {
                                var60 = [0.7027027027027027, 0.2972972972972973];
                            }
                        } else {
                            var60 = [1.0, 0.0];
                        }
                    } else {
                        var60 = [0.6, 0.4];
                    }
                } else {
                    if (input[13] <= 3.840999960899353) {
                        if (input[1] <= 14.5) {
                            if (input[9] <= 0.5) {
                                var60 = [0.9712230215827338, 0.02877697841726619];
                            } else {
                                var60 = [0.95, 0.05];
                            }
                        } else {
                            if (input[2] <= 1.5) {
                                var60 = [0.7966101694915254, 0.2033898305084746];
                            } else {
                                var60 = [0.9342105263157895, 0.06578947368421052];
                            }
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            if (input[0] <= 36.5) {
                                var60 = [0.75, 0.25];
                            } else {
                                var60 = [0.1111111111111111, 0.8888888888888888];
                            }
                        } else {
                            var60 = [1.0, 0.0];
                        }
                    }
                }
            } else {
                var60 = [0.0, 1.0];
            }
        } else {
            if (input[12] <= 1.5) {
                if (input[1] <= 7.5) {
                    var60 = [1.0, 0.0];
                } else {
                    if (input[2] <= 2.5) {
                        if (input[1] <= 19.5) {
                            if (input[0] <= 51.5) {
                                var60 = [0.8787878787878788, 0.12121212121212122];
                            } else {
                                var60 = [0.19480519480519481, 0.8051948051948052];
                            }
                        } else {
                            if (input[0] <= 51.5) {
                                var60 = [0.5675675675675675, 0.43243243243243246];
                            } else {
                                var60 = [0.016203703703703703, 0.9837962962962963];
                            }
                        }
                    } else {
                        if (input[3] <= 0.5) {
                            if (input[1] <= 23.5) {
                                var60 = [0.5, 0.5];
                            } else {
                                var60 = [0.0, 1.0];
                            }
                        } else {
                            var60 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                if (input[11] <= 0.5) {
                    var60 = [0.0, 1.0];
                } else {
                    if (input[1] <= 29.0) {
                        if (input[2] <= 2.5) {
                            if (input[0] <= 59.5) {
                                var60 = [0.9863636363636363, 0.013636363636363636];
                            } else {
                                var60 = [0.125, 0.875];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var60 = [0.0, 1.0];
                            } else {
                                var60 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[2] <= 3.5) {
                            var60 = [0.0, 1.0];
                        } else {
                            if (input[9] <= 1.5) {
                                var60 = [0.3333333333333333, 0.6666666666666666];
                            } else {
                                var60 = [0.0, 1.0];
                            }
                        }
                    }
                }
            }
        }
    } else {
        var60 = [0.0, 1.0];
    }
    var var61;
    if (input[3] <= 0.5) {
        if (input[10] <= 0.5) {
            if (input[7] <= 0.5) {
                if (input[1] <= 19.5) {
                    if (input[12] <= 0.5) {
                        if (input[0] <= 35.5) {
                            if (input[1] <= 14.5) {
                                var61 = [0.8866666666666667, 0.11333333333333333];
                            } else {
                                var61 = [1.0, 0.0];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var61 = [0.09836065573770492, 0.9016393442622951];
                            } else {
                                var61 = [0.42857142857142855, 0.5714285714285714];
                            }
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[13] <= 2.8604999780654907) {
                                var61 = [0.8, 0.2];
                            } else {
                                var61 = [0.1694915254237288, 0.8305084745762712];
                            }
                        } else {
                            var61 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[6] <= 0.5) {
                        if (input[13] <= 3.7415000200271606) {
                            if (input[11] <= 0.5) {
                                var61 = [0.8888888888888888, 0.1111111111111111];
                            } else {
                                var61 = [0.6666666666666666, 0.3333333333333333];
                            }
                        } else {
                            var61 = [0.0, 1.0];
                        }
                    } else {
                        if (input[13] <= 3.7165000438690186) {
                            if (input[6] <= 2.5) {
                                var61 = [0.03117505995203837, 0.9688249400479616];
                            } else {
                                var61 = [0.0, 1.0];
                            }
                        } else {
                            if (input[2] <= 2.5) {
                                var61 = [0.15217391304347827, 0.8478260869565217];
                            } else {
                                var61 = [0.024793388429752067, 0.9752066115702479];
                            }
                        }
                    }
                }
            } else {
                var61 = [1.0, 0.0];
            }
        } else {
            if (input[12] <= 0.5) {
                var61 = [0.16666666666666666, 0.8333333333333334];
            } else {
                if (input[0] <= 51.5) {
                    if (input[13] <= 3.4584999084472656) {
                        var61 = [0.0, 1.0];
                    } else {
                        var61 = [0.6, 0.4];
                    }
                } else {
                    var61 = [0.0, 1.0];
                }
            }
        }
    } else {
        var61 = [0.0, 1.0];
    }
    var var62;
    if (input[13] <= 2.909000039100647) {
        if (input[1] <= 11.5) {
            if (input[0] <= 47.5) {
                if (input[11] <= 0.5) {
                    var62 = [0.9633911368015414, 0.036608863198458574];
                } else {
                    var62 = [1.0, 0.0];
                }
            } else {
                var62 = [0.0, 1.0];
            }
        } else {
            if (input[13] <= 2.8485000133514404) {
                if (input[7] <= 0.5) {
                    if (input[2] <= 2.5) {
                        if (input[0] <= 42.0) {
                            var62 = [0.75, 0.25];
                        } else {
                            var62 = [0.0, 1.0];
                        }
                    } else {
                        if (input[1] <= 13.5) {
                            if (input[13] <= 2.8035000562667847) {
                                var62 = [0.0, 1.0];
                            } else {
                                var62 = [0.02247191011235955, 0.9775280898876404];
                            }
                        } else {
                            var62 = [0.0, 1.0];
                        }
                    }
                } else {
                    var62 = [1.0, 0.0];
                }
            } else {
                if (input[3] <= 0.5) {
                    if (input[0] <= 47.5) {
                        if (input[1] <= 15.5) {
                            var62 = [1.0, 0.0];
                        } else {
                            var62 = [0.5, 0.5];
                        }
                    } else {
                        var62 = [0.5, 0.5];
                    }
                } else {
                    var62 = [0.0, 1.0];
                }
            }
        }
    } else {
        if (input[2] <= 2.5) {
            if (input[0] <= 57.5) {
                if (input[10] <= 0.5) {
                    if (input[5] <= 1.5) {
                        if (input[7] <= 0.5) {
                            if (input[13] <= 3.534000039100647) {
                                var62 = [0.6462882096069869, 0.3537117903930131];
                            } else {
                                var62 = [0.43478260869565216, 0.5652173913043478];
                            }
                        } else {
                            var62 = [1.0, 0.0];
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[7] <= 0.5) {
                                var62 = [0.0, 1.0];
                            } else {
                                var62 = [1.0, 0.0];
                            }
                        } else {
                            var62 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[6] <= 0.5) {
                        var62 = [0.0, 1.0];
                    } else {
                        var62 = [0.6666666666666666, 0.3333333333333333];
                    }
                }
            } else {
                if (input[0] <= 60.5) {
                    if (input[12] <= 1.5) {
                        var62 = [0.16666666666666666, 0.8333333333333334];
                    } else {
                        if (input[1] <= 27.5) {
                            var62 = [1.0, 0.0];
                        } else {
                            var62 = [0.2222222222222222, 0.7777777777777778];
                        }
                    }
                } else {
                    if (input[7] <= 0.5) {
                        if (input[1] <= 25.5) {
                            var62 = [0.0, 1.0];
                        } else {
                            if (input[12] <= 0.5) {
                                var62 = [0.037037037037037035, 0.9629629629629629];
                            } else {
                                var62 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var62 = [1.0, 0.0];
                    }
                }
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[6] <= 1.0) {
                    var62 = [0.0, 1.0];
                } else {
                    if (input[11] <= 0.5) {
                        if (input[0] <= 40.0) {
                            if (input[13] <= 3.6790000200271606) {
                                var62 = [1.0, 0.0];
                            } else {
                                var62 = [0.5, 0.5];
                            }
                        } else {
                            var62 = [0.0, 1.0];
                        }
                    } else {
                        var62 = [0.0, 1.0];
                    }
                }
            } else {
                var62 = [1.0, 0.0];
            }
        }
    }
    var var63;
    if (input[12] <= 2.5) {
        if (input[7] <= 0.5) {
            if (input[0] <= 28.5) {
                if (input[0] <= 23.5) {
                    if (input[0] <= 20.5) {
                        var63 = [1.0, 0.0];
                    } else {
                        if (input[1] <= 10.0) {
                            if (input[1] <= 8.0) {
                                var63 = [1.0, 0.0];
                            } else {
                                var63 = [0.3333333333333333, 0.6666666666666666];
                            }
                        } else {
                            var63 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[2] <= 1.5) {
                        var63 = [0.72, 0.28];
                    } else {
                        if (input[13] <= 3.503000020980835) {
                            if (input[1] <= 14.5) {
                                var63 = [0.8, 0.2];
                            } else {
                                var63 = [1.0, 0.0];
                            }
                        } else {
                            var63 = [0.5, 0.5];
                        }
                    }
                }
            } else {
                if (input[11] <= 0.5) {
                    if (input[0] <= 38.5) {
                        if (input[1] <= 15.5) {
                            if (input[0] <= 29.5) {
                                var63 = [0.2727272727272727, 0.7272727272727273];
                            } else {
                                var63 = [0.08571428571428572, 0.9142857142857143];
                            }
                        } else {
                            if (input[13] <= 3.8545000553131104) {
                                var63 = [0.8846153846153846, 0.11538461538461539];
                            } else {
                                var63 = [0.18181818181818182, 0.8181818181818182];
                            }
                        }
                    } else {
                        if (input[0] <= 41.5) {
                            if (input[3] <= 0.5) {
                                var63 = [0.26666666666666666, 0.7333333333333333];
                            } else {
                                var63 = [0.0, 1.0];
                            }
                        } else {
                            if (input[2] <= 2.5) {
                                var63 = [0.01576872536136662, 0.9842312746386334];
                            } else {
                                var63 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[9] <= 0.5) {
                        if (input[6] <= 1.5) {
                            if (input[2] <= 2.5) {
                                var63 = [0.6666666666666666, 0.3333333333333333];
                            } else {
                                var63 = [0.0, 1.0];
                            }
                        } else {
                            var63 = [0.0, 1.0];
                        }
                    } else {
                        var63 = [0.0, 1.0];
                    }
                }
            }
        } else {
            var63 = [1.0, 0.0];
        }
    } else {
        var63 = [0.0, 1.0];
    }
    var var64;
    if (input[0] <= 40.5) {
        if (input[13] <= 2.9049999713897705) {
            if (input[6] <= 0.5) {
                if (input[3] <= 0.5) {
                    if (input[13] <= 2.8739999532699585) {
                        if (input[13] <= 2.575000047683716) {
                            var64 = [1.0, 0.0];
                        } else {
                            if (input[7] <= 0.5) {
                                var64 = [0.8095238095238095, 0.19047619047619047];
                            } else {
                                var64 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var64 = [0.75, 0.25];
                    }
                } else {
                    var64 = [0.0, 1.0];
                }
            } else {
                var64 = [1.0, 0.0];
            }
        } else {
            if (input[0] <= 34.5) {
                if (input[3] <= 0.5) {
                    if (input[7] <= 0.5) {
                        if (input[13] <= 2.9394999742507935) {
                            if (input[2] <= 1.5) {
                                var64 = [0.3333333333333333, 0.6666666666666666];
                            } else {
                                var64 = [1.0, 0.0];
                            }
                        } else {
                            if (input[0] <= 33.5) {
                                var64 = [0.9457364341085271, 0.05426356589147287];
                            } else {
                                var64 = [0.5, 0.5];
                            }
                        }
                    } else {
                        var64 = [1.0, 0.0];
                    }
                } else {
                    var64 = [0.0, 1.0];
                }
            } else {
                if (input[2] <= 2.5) {
                    if (input[13] <= 3.9110000133514404) {
                        if (input[7] <= 0.5) {
                            if (input[10] <= 0.5) {
                                var64 = [0.49122807017543857, 0.5087719298245614];
                            } else {
                                var64 = [0.0, 1.0];
                            }
                        } else {
                            var64 = [1.0, 0.0];
                        }
                    } else {
                        if (input[1] <= 26.0) {
                            var64 = [0.25, 0.75];
                        } else {
                            var64 = [0.25, 0.75];
                        }
                    }
                } else {
                    if (input[6] <= 1.0) {
                        var64 = [0.0, 1.0];
                    } else {
                        var64 = [1.0, 0.0];
                    }
                }
            }
        }
    } else {
        if (input[2] <= 2.5) {
            if (input[0] <= 56.5) {
                if (input[10] <= 0.5) {
                    if (input[5] <= 1.5) {
                        if (input[0] <= 48.5) {
                            if (input[0] <= 44.5) {
                                var64 = [0.9657534246575342, 0.03424657534246575];
                            } else {
                                var64 = [0.8888888888888888, 0.1111111111111111];
                            }
                        } else {
                            if (input[2] <= 1.5) {
                                var64 = [0.6363636363636364, 0.36363636363636365];
                            } else {
                                var64 = [0.8433734939759037, 0.1566265060240964];
                            }
                        }
                    } else {
                        var64 = [0.0, 1.0];
                    }
                } else {
                    if (input[1] <= 18.5) {
                        var64 = [0.3333333333333333, 0.6666666666666666];
                    } else {
                        var64 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[6] <= 0.5) {
                    if (input[10] <= 0.5) {
                        if (input[13] <= 3.4255000352859497) {
                            var64 = [0.0, 1.0];
                        } else {
                            if (input[13] <= 3.728500008583069) {
                                var64 = [0.5, 0.5];
                            } else {
                                var64 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var64 = [0.0, 1.0];
                    }
                } else {
                    if (input[11] <= 0.5) {
                        if (input[0] <= 59.5) {
                            if (input[13] <= 3.624000072479248) {
                                var64 = [0.0, 1.0];
                            } else {
                                var64 = [0.7142857142857143, 0.2857142857142857];
                            }
                        } else {
                            if (input[0] <= 64.5) {
                                var64 = [0.125, 0.875];
                            } else {
                                var64 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[1] <= 19.5) {
                            var64 = [0.8, 0.2];
                        } else {
                            if (input[7] <= 0.5) {
                                var64 = [0.027777777777777776, 0.9722222222222222];
                            } else {
                                var64 = [1.0, 0.0];
                            }
                        }
                    }
                }
            }
        } else {
            if (input[7] <= 0.5) {
                var64 = [0.0, 1.0];
            } else {
                var64 = [1.0, 0.0];
            }
        }
    }
    var var65;
    if (input[1] <= 11.5) {
        if (input[4] <= 0.5) {
            if (input[0] <= 48.5) {
                if (input[1] <= 10.5) {
                    if (input[7] <= 0.5) {
                        if (input[3] <= 0.5) {
                            if (input[12] <= 0.5) {
                                var65 = [0.8846153846153846, 0.11538461538461539];
                            } else {
                                var65 = [0.5714285714285714, 0.42857142857142855];
                            }
                        } else {
                            var65 = [0.0, 1.0];
                        }
                    } else {
                        var65 = [1.0, 0.0];
                    }
                } else {
                    if (input[6] <= 0.5) {
                        if (input[5] <= 0.5) {
                            if (input[0] <= 36.5) {
                                var65 = [0.9699248120300752, 0.03007518796992481];
                            } else {
                                var65 = [0.47058823529411764, 0.5294117647058824];
                            }
                        } else {
                            var65 = [1.0, 0.0];
                        }
                    } else {
                        var65 = [1.0, 0.0];
                    }
                }
            } else {
                var65 = [0.0, 1.0];
            }
        } else {
            var65 = [0.0, 1.0];
        }
    } else {
        if (input[7] <= 0.5) {
            if (input[0] <= 29.5) {
                var65 = [0.8431372549019608, 0.1568627450980392];
            } else {
                if (input[0] <= 37.5) {
                    if (input[1] <= 15.5) {
                        if (input[1] <= 12.5) {
                            var65 = [0.2727272727272727, 0.7272727272727273];
                        } else {
                            if (input[1] <= 14.5) {
                                var65 = [0.030612244897959183, 0.9693877551020408];
                            } else {
                                var65 = [0.10344827586206896, 0.896551724137931];
                            }
                        }
                    } else {
                        if (input[13] <= 3.784000039100647) {
                            if (input[9] <= 0.5) {
                                var65 = [0.7407407407407407, 0.25925925925925924];
                            } else {
                                var65 = [1.0, 0.0];
                            }
                        } else {
                            if (input[13] <= 3.8585000038146973) {
                                var65 = [0.42857142857142855, 0.5714285714285714];
                            } else {
                                var65 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[0] <= 54.5) {
                        if (input[11] <= 0.5) {
                            if (input[13] <= 3.1894999742507935) {
                                var65 = [0.0, 1.0];
                            } else {
                                var65 = [0.08695652173913043, 0.9130434782608695];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var65 = [0.2222222222222222, 0.7777777777777778];
                            } else {
                                var65 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[11] <= 0.5) {
                            var65 = [0.0, 1.0];
                        } else {
                            if (input[12] <= 2.5) {
                                var65 = [0.02702702702702703, 0.972972972972973];
                            } else {
                                var65 = [0.0, 1.0];
                            }
                        }
                    }
                }
            }
        } else {
            var65 = [1.0, 0.0];
        }
    }
    var var66;
    if (input[1] <= 11.5) {
        if (input[1] <= 10.5) {
            if (input[7] <= 0.5) {
                if (input[12] <= 0.5) {
                    if (input[0] <= 26.5) {
                        if (input[0] <= 20.5) {
                            var66 = [1.0, 0.0];
                        } else {
                            if (input[1] <= 8.0) {
                                var66 = [1.0, 0.0];
                            } else {
                                var66 = [0.8181818181818182, 0.18181818181818182];
                            }
                        }
                    } else {
                        if (input[6] <= 0.5) {
                            var66 = [0.2608695652173913, 0.7391304347826086];
                        } else {
                            var66 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[12] <= 1.5) {
                        var66 = [0.0, 1.0];
                    } else {
                        if (input[0] <= 59.5) {
                            var66 = [1.0, 0.0];
                        } else {
                            var66 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var66 = [1.0, 0.0];
            }
        } else {
            if (input[12] <= 4.5) {
                if (input[3] <= 0.5) {
                    if (input[9] <= 1.5) {
                        if (input[12] <= 0.5) {
                            if (input[6] <= 0.5) {
                                var66 = [0.9935064935064936, 0.006493506493506494];
                            } else {
                                var66 = [1.0, 0.0];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var66 = [0.8333333333333334, 0.16666666666666666];
                            } else {
                                var66 = [0.8181818181818182, 0.18181818181818182];
                            }
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            var66 = [0.5, 0.5];
                        } else {
                            var66 = [1.0, 0.0];
                        }
                    }
                } else {
                    var66 = [0.0, 1.0];
                }
            } else {
                var66 = [0.0, 1.0];
            }
        }
    } else {
        if (input[0] <= 40.5) {
            if (input[13] <= 2.847000002861023) {
                if (input[6] <= 0.5) {
                    if (input[7] <= 0.5) {
                        var66 = [0.0, 1.0];
                    } else {
                        var66 = [1.0, 0.0];
                    }
                } else {
                    var66 = [1.0, 0.0];
                }
            } else {
                if (input[3] <= 0.5) {
                    if (input[13] <= 3.8545000553131104) {
                        if (input[0] <= 33.5) {
                            if (input[0] <= 27.5) {
                                var66 = [0.9977678571428571, 0.002232142857142857];
                            } else {
                                var66 = [0.9867424242424242, 0.013257575757575758];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var66 = [0.7894736842105263, 0.21052631578947367];
                            } else {
                                var66 = [0.952755905511811, 0.047244094488188976];
                            }
                        }
                    } else {
                        if (input[6] <= 0.5) {
                            var66 = [0.7142857142857143, 0.2857142857142857];
                        } else {
                            if (input[1] <= 23.5) {
                                var66 = [0.9, 0.1];
                            } else {
                                var66 = [0.2631578947368421, 0.7368421052631579];
                            }
                        }
                    }
                } else {
                    var66 = [0.0, 1.0];
                }
            }
        } else {
            if (input[6] <= 0.5) {
                if (input[0] <= 56.5) {
                    if (input[12] <= 1.5) {
                        if (input[7] <= 0.5) {
                            if (input[12] <= 0.5) {
                                var66 = [0.006956521739130435, 0.9930434782608696];
                            } else {
                                var66 = [0.0, 1.0];
                            }
                        } else {
                            var66 = [1.0, 0.0];
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[13] <= 2.9499999284744263) {
                                var66 = [0.06666666666666667, 0.9333333333333333];
                            } else {
                                var66 = [1.0, 0.0];
                            }
                        } else {
                            var66 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[5] <= 1.5) {
                        if (input[13] <= 3.635499954223633) {
                            var66 = [0.0, 1.0];
                        } else {
                            if (input[11] <= 2.0) {
                                var66 = [0.25, 0.75];
                            } else {
                                var66 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[1] <= 23.5) {
                            var66 = [0.0, 1.0];
                        } else {
                            var66 = [0.4, 0.6];
                        }
                    }
                }
            } else {
                if (input[0] <= 59.5) {
                    if (input[1] <= 19.5) {
                        if (input[13] <= 3.723499894142151) {
                            if (input[7] <= 0.5) {
                                var66 = [0.625, 0.375];
                            } else {
                                var66 = [1.0, 0.0];
                            }
                        } else {
                            var66 = [0.8, 0.2];
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            if (input[13] <= 3.427500009536743) {
                                var66 = [0.25, 0.75];
                            } else {
                                var66 = [0.016666666666666666, 0.9833333333333333];
                            }
                        } else {
                            var66 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[13] <= 3.7165000438690186) {
                        var66 = [0.0, 1.0];
                    } else {
                        if (input[13] <= 3.727500081062317) {
                            var66 = [0.25, 0.75];
                        } else {
                            if (input[13] <= 3.9394999742507935) {
                                var66 = [0.04, 0.96];
                            } else {
                                var66 = [0.0, 1.0];
                            }
                        }
                    }
                }
            }
        }
    }
    var var67;
    if (input[7] <= 0.5) {
        if (input[0] <= 28.5) {
            if (input[6] <= 0.5) {
                if (input[1] <= 9.5) {
                    var67 = [1.0, 0.0];
                } else {
                    if (input[3] <= 0.5) {
                        if (input[9] <= 0.5) {
                            if (input[0] <= 23.5) {
                                var67 = [1.0, 0.0];
                            } else {
                                var67 = [0.8888888888888888, 0.1111111111111111];
                            }
                        } else {
                            var67 = [1.0, 0.0];
                        }
                    } else {
                        var67 = [0.0, 1.0];
                    }
                }
            } else {
                var67 = [1.0, 0.0];
            }
        } else {
            if (input[3] <= 0.5) {
                if (input[6] <= 2.5) {
                    if (input[1] <= 19.5) {
                        if (input[0] <= 36.5) {
                            if (input[6] <= 0.5) {
                                var67 = [0.5517241379310345, 0.4482758620689655];
                            } else {
                                var67 = [1.0, 0.0];
                            }
                        } else {
                            if (input[10] <= 0.5) {
                                var67 = [0.1417910447761194, 0.8582089552238806];
                            } else {
                                var67 = [0.09090909090909091, 0.9090909090909091];
                            }
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[2] <= 2.5) {
                                var67 = [0.09691629955947137, 0.9030837004405287];
                            } else {
                                var67 = [0.010101010101010102, 0.98989898989899];
                            }
                        } else {
                            if (input[12] <= 0.5) {
                                var67 = [0.0353356890459364, 0.9646643109540636];
                            } else {
                                var67 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    var67 = [0.0, 1.0];
                }
            } else {
                var67 = [0.0, 1.0];
            }
        }
    } else {
        var67 = [1.0, 0.0];
    }
    var var68;
    if (input[7] <= 0.5) {
        if (input[0] <= 28.5) {
            if (input[3] <= 0.5) {
                if (input[1] <= 14.5) {
                    if (input[0] <= 23.5) {
                        if (input[0] <= 20.5) {
                            var68 = [1.0, 0.0];
                        } else {
                            if (input[13] <= 2.697499990463257) {
                                var68 = [0.8888888888888888, 0.1111111111111111];
                            } else {
                                var68 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[0] <= 27.5) {
                            if (input[6] <= 0.5) {
                                var68 = [0.75, 0.25];
                            } else {
                                var68 = [1.0, 0.0];
                            }
                        } else {
                            if (input[13] <= 3.309000015258789) {
                                var68 = [0.8181818181818182, 0.18181818181818182];
                            } else {
                                var68 = [0.4, 0.6];
                            }
                        }
                    }
                } else {
                    var68 = [1.0, 0.0];
                }
            } else {
                var68 = [0.0, 1.0];
            }
        } else {
            if (input[0] <= 38.5) {
                if (input[13] <= 3.08050000667572) {
                    if (input[0] <= 35.5) {
                        if (input[3] <= 0.5) {
                            if (input[13] <= 2.9394999742507935) {
                                var68 = [0.46153846153846156, 0.5384615384615384];
                            } else {
                                var68 = [1.0, 0.0];
                            }
                        } else {
                            var68 = [0.0, 1.0];
                        }
                    } else {
                        if (input[11] <= 0.5) {
                            if (input[13] <= 2.897499918937683) {
                                var68 = [0.0, 1.0];
                            } else {
                                var68 = [0.2, 0.8];
                            }
                        } else {
                            var68 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[6] <= 0.5) {
                        if (input[1] <= 11.5) {
                            var68 = [1.0, 0.0];
                        } else {
                            if (input[5] <= 1.0) {
                                var68 = [0.5, 0.5];
                            } else {
                                var68 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[2] <= 2.5) {
                            if (input[5] <= 2.0) {
                                var68 = [0.8723404255319149, 0.1276595744680851];
                            } else {
                                var68 = [0.0, 1.0];
                            }
                        } else {
                            if (input[0] <= 34.0) {
                                var68 = [0.6666666666666666, 0.3333333333333333];
                            } else {
                                var68 = [1.0, 0.0];
                            }
                        }
                    }
                }
            } else {
                if (input[2] <= 2.5) {
                    if (input[13] <= 3.6549999713897705) {
                        if (input[1] <= 19.5) {
                            if (input[2] <= 1.5) {
                                var68 = [0.06060606060606061, 0.9393939393939394];
                            } else {
                                var68 = [0.5714285714285714, 0.42857142857142855];
                            }
                        } else {
                            if (input[10] <= 0.5) {
                                var68 = [0.029940119760479042, 0.9700598802395209];
                            } else {
                                var68 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[11] <= 0.5) {
                            if (input[9] <= 0.5) {
                                var68 = [0.023529411764705882, 0.9764705882352941];
                            } else {
                                var68 = [0.0, 1.0];
                            }
                        } else {
                            if (input[12] <= 2.5) {
                                var68 = [0.041666666666666664, 0.9583333333333334];
                            } else {
                                var68 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    var68 = [0.0, 1.0];
                }
            }
        }
    } else {
        var68 = [1.0, 0.0];
    }
    var var69;
    if (input[7] <= 0.5) {
        if (input[2] <= 2.5) {
            if (input[12] <= 0.5) {
                if (input[0] <= 38.5) {
                    if (input[5] <= 1.5) {
                        if (input[6] <= 0.5) {
                            if (input[0] <= 23.5) {
                                var69 = [0.9591836734693877, 0.04081632653061224];
                            } else {
                                var69 = [0.546875, 0.453125];
                            }
                        } else {
                            if (input[0] <= 36.5) {
                                var69 = [0.9787234042553191, 0.02127659574468085];
                            } else {
                                var69 = [0.6666666666666666, 0.3333333333333333];
                            }
                        }
                    } else {
                        var69 = [0.0, 1.0];
                    }
                } else {
                    if (input[5] <= 0.5) {
                        if (input[0] <= 51.5) {
                            if (input[1] <= 14.0) {
                                var69 = [0.6666666666666666, 0.3333333333333333];
                            } else {
                                var69 = [0.15384615384615385, 0.8461538461538461];
                            }
                        } else {
                            var69 = [0.0, 1.0];
                        }
                    } else {
                        var69 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[6] <= 0.5) {
                    if (input[1] <= 13.5) {
                        if (input[0] <= 50.0) {
                            if (input[1] <= 9.5) {
                                var69 = [1.0, 0.0];
                            } else {
                                var69 = [0.15789473684210525, 0.8421052631578947];
                            }
                        } else {
                            var69 = [0.0, 1.0];
                        }
                    } else {
                        if (input[12] <= 2.5) {
                            if (input[1] <= 20.5) {
                                var69 = [0.14285714285714285, 0.8571428571428571];
                            } else {
                                var69 = [0.0, 1.0];
                            }
                        } else {
                            var69 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[11] <= 0.5) {
                        var69 = [0.0, 1.0];
                    } else {
                        if (input[12] <= 2.5) {
                            if (input[1] <= 27.5) {
                                var69 = [0.7272727272727273, 0.2727272727272727];
                            } else {
                                var69 = [0.0, 1.0];
                            }
                        } else {
                            var69 = [0.0, 1.0];
                        }
                    }
                }
            }
        } else {
            if (input[6] <= 1.0) {
                var69 = [0.0, 1.0];
            } else {
                if (input[13] <= 3.2545000314712524) {
                    var69 = [1.0, 0.0];
                } else {
                    if (input[1] <= 22.5) {
                        if (input[13] <= 3.60699999332428) {
                            var69 = [1.0, 0.0];
                        } else {
                            var69 = [0.0, 1.0];
                        }
                    } else {
                        var69 = [0.0, 1.0];
                    }
                }
            }
        }
    } else {
        var69 = [1.0, 0.0];
    }
    var var70;
    if (input[13] <= 2.909000039100647) {
        if (input[7] <= 0.5) {
            if (input[2] <= 2.5) {
                if (input[1] <= 15.0) {
                    if (input[0] <= 26.5) {
                        if (input[9] <= 0.5) {
                            if (input[13] <= 2.6134999990463257) {
                                var70 = [1.0, 0.0];
                            } else {
                                var70 = [0.9333333333333333, 0.06666666666666667];
                            }
                        } else {
                            var70 = [1.0, 0.0];
                        }
                    } else {
                        if (input[0] <= 29.5) {
                            var70 = [0.25, 0.75];
                        } else {
                            if (input[0] <= 39.0) {
                                var70 = [0.8181818181818182, 0.18181818181818182];
                            } else {
                                var70 = [0.3333333333333333, 0.6666666666666666];
                            }
                        }
                    }
                } else {
                    var70 = [0.0, 1.0];
                }
            } else {
                if (input[0] <= 26.5) {
                    var70 = [0.3333333333333333, 0.6666666666666666];
                } else {
                    var70 = [0.0, 1.0];
                }
            }
        } else {
            var70 = [1.0, 0.0];
        }
    } else {
        if (input[3] <= 0.5) {
            if (input[10] <= 0.5) {
                if (input[7] <= 0.5) {
                    if (input[13] <= 3.3769999742507935) {
                        if (input[0] <= 36.5) {
                            if (input[6] <= 0.5) {
                                var70 = [0.8709677419354839, 0.12903225806451613];
                            } else {
                                var70 = [1.0, 0.0];
                            }
                        } else {
                            if (input[0] <= 50.5) {
                                var70 = [0.43243243243243246, 0.5675675675675675];
                            } else {
                                var70 = [0.03125, 0.96875];
                            }
                        }
                    } else {
                        if (input[12] <= 0.5) {
                            if (input[9] <= 0.5) {
                                var70 = [0.20863309352517986, 0.7913669064748201];
                            } else {
                                var70 = [0.02247191011235955, 0.9775280898876404];
                            }
                        } else {
                            if (input[11] <= 0.5) {
                                var70 = [0.0, 1.0];
                            } else {
                                var70 = [0.048, 0.952];
                            }
                        }
                    }
                } else {
                    var70 = [1.0, 0.0];
                }
            } else {
                var70 = [0.0, 1.0];
            }
        } else {
            var70 = [0.0, 1.0];
        }
    }
    var var71;
    if (input[0] <= 40.5) {
        if (input[11] <= 0.5) {
            if (input[2] <= 2.5) {
                if (input[10] <= 0.5) {
                    if (input[0] <= 33.5) {
                        if (input[0] <= 25.5) {
                            if (input[13] <= 2.643999934196472) {
                                var71 = [0.9901477832512315, 0.009852216748768473];
                            } else {
                                var71 = [0.9991431019708654, 0.000856898029134533];
                            }
                        } else {
                            if (input[9] <= 1.5) {
                                var71 = [0.9894613583138173, 0.01053864168618267];
                            } else {
                                var71 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[13] <= 3.773500084877014) {
                                var71 = [0.9204545454545454, 0.07954545454545454];
                            } else {
                                var71 = [0.5, 0.5];
                            }
                        } else {
                            if (input[1] <= 10.0) {
                                var71 = [0.8, 0.2];
                            } else {
                                var71 = [1.0, 0.0];
                            }
                        }
                    }
                } else {
                    var71 = [0.0, 1.0];
                }
            } else {
                if (input[6] <= 1.0) {
                    var71 = [0.0, 1.0];
                } else {
                    var71 = [1.0, 0.0];
                }
            }
        } else {
            if (input[12] <= 1.5) {
                var71 = [0.0, 1.0];
            } else {
                if (input[0] <= 36.0) {
                    var71 = [0.0, 1.0];
                } else {
                    var71 = [0.9428571428571428, 0.05714285714285714];
                }
            }
        }
    } else {
        if (input[2] <= 2.5) {
            if (input[9] <= 0.5) {
                if (input[2] <= 1.5) {
                    if (input[0] <= 51.5) {
                        if (input[12] <= 1.5) {
                            if (input[7] <= 0.5) {
                                var71 = [0.36363636363636365, 0.6363636363636364];
                            } else {
                                var71 = [1.0, 0.0];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var71 = [0.6363636363636364, 0.36363636363636365];
                            } else {
                                var71 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[0] <= 61.0) {
                            if (input[1] <= 13.5) {
                                var71 = [0.0, 1.0];
                            } else {
                                var71 = [0.84375, 0.15625];
                            }
                        } else {
                            var71 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[13] <= 3.3830000162124634) {
                        if (input[11] <= 0.5) {
                            if (input[12] <= 0.5) {
                                var71 = [0.9454545454545454, 0.05454545454545454];
                            } else {
                                var71 = [0.0, 1.0];
                            }
                        } else {
                            if (input[0] <= 55.5) {
                                var71 = [1.0, 0.0];
                            } else {
                                var71 = [0.25, 0.75];
                            }
                        }
                    } else {
                        if (input[11] <= 0.5) {
                            if (input[8] <= 0.5) {
                                var71 = [0.24752475247524752, 0.7524752475247525];
                            } else {
                                var71 = [0.0, 1.0];
                            }
                        } else {
                            if (input[0] <= 62.5) {
                                var71 = [1.0, 0.0];
                            } else {
                                var71 = [0.0, 1.0];
                            }
                        }
                    }
                }
            } else {
                if (input[9] <= 1.5) {
                    if (input[0] <= 47.5) {
                        if (input[13] <= 3.4325000047683716) {
                            if (input[6] <= 0.5) {
                                var71 = [0.5, 0.5];
                            } else {
                                var71 = [1.0, 0.0];
                            }
                        } else {
                            var71 = [1.0, 0.0];
                        }
                    } else {
                        var71 = [0.0, 1.0];
                    }
                } else {
                    if (input[1] <= 23.5) {
                        var71 = [0.0, 1.0];
                    } else {
                        if (input[7] <= 0.5) {
                            var71 = [0.0, 1.0];
                        } else {
                            var71 = [1.0, 0.0];
                        }
                    }
                }
            }
        } else {
            if (input[6] <= 1.0) {
                var71 = [0.0, 1.0];
            } else {
                if (input[12] <= 2.5) {
                    if (input[13] <= 3.5460000038146973) {
                        if (input[7] <= 0.5) {
                            var71 = [0.0, 1.0];
                        } else {
                            var71 = [1.0, 0.0];
                        }
                    } else {
                        if (input[13] <= 3.7634999752044678) {
                            if (input[2] <= 3.5) {
                                var71 = [0.6363636363636364, 0.36363636363636365];
                            } else {
                                var71 = [0.0, 1.0];
                            }
                        } else {
                            var71 = [0.0, 1.0];
                        }
                    }
                } else {
                    var71 = [0.0, 1.0];
                }
            }
        }
    }
    var var72;
    if (input[7] <= 0.5) {
        if (input[1] <= 10.5) {
            if (input[13] <= 3.146000027656555) {
                if (input[12] <= 0.5) {
                    if (input[2] <= 2.5) {
                        if (input[0] <= 43.5) {
                            if (input[9] <= 0.5) {
                                var72 = [0.9310344827586207, 0.06896551724137931];
                            } else {
                                var72 = [1.0, 0.0];
                            }
                        } else {
                            var72 = [0.0, 1.0];
                        }
                    } else {
                        var72 = [0.0, 1.0];
                    }
                } else {
                    if (input[13] <= 2.9739999771118164) {
                        var72 = [0.875, 0.125];
                    } else {
                        if (input[13] <= 3.0609999895095825) {
                            var72 = [0.0, 1.0];
                        } else {
                            var72 = [0.6666666666666666, 0.3333333333333333];
                        }
                    }
                }
            } else {
                var72 = [0.0, 1.0];
            }
        } else {
            if (input[3] <= 0.5) {
                if (input[12] <= 0.5) {
                    if (input[0] <= 36.5) {
                        if (input[0] <= 33.5) {
                            if (input[0] <= 23.5) {
                                var72 = [1.0, 0.0];
                            } else {
                                var72 = [0.9347826086956522, 0.06521739130434782];
                            }
                        } else {
                            if (input[0] <= 34.5) {
                                var72 = [0.3333333333333333, 0.6666666666666666];
                            } else {
                                var72 = [0.6571428571428571, 0.34285714285714286];
                            }
                        }
                    } else {
                        if (input[0] <= 42.5) {
                            if (input[9] <= 0.5) {
                                var72 = [0.27906976744186046, 0.7209302325581395];
                            } else {
                                var72 = [0.5714285714285714, 0.42857142857142855];
                            }
                        } else {
                            if (input[5] <= 0.5) {
                                var72 = [0.011574074074074073, 0.9884259259259259];
                            } else {
                                var72 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[1] <= 17.5) {
                        if (input[12] <= 2.5) {
                            if (input[5] <= 0.5) {
                                var72 = [0.38461538461538464, 0.6153846153846154];
                            } else {
                                var72 = [0.0, 1.0];
                            }
                        } else {
                            var72 = [0.0, 1.0];
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[12] <= 2.5) {
                                var72 = [0.045871559633027525, 0.9541284403669725];
                            } else {
                                var72 = [0.0, 1.0];
                            }
                        } else {
                            var72 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var72 = [0.0, 1.0];
            }
        }
    } else {
        var72 = [1.0, 0.0];
    }
    var var73;
    if (input[2] <= 2.5) {
        if (input[10] <= 0.5) {
            if (input[9] <= 1.5) {
                if (input[1] <= 19.5) {
                    if (input[0] <= 56.5) {
                        if (input[7] <= 0.5) {
                            if (input[5] <= 1.5) {
                                var73 = [0.7849829351535836, 0.2150170648464164];
                            } else {
                                var73 = [0.0, 1.0];
                            }
                        } else {
                            var73 = [1.0, 0.0];
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            var73 = [0.0, 1.0];
                        } else {
                            var73 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[0] <= 59.5) {
                        if (input[11] <= 0.5) {
                            if (input[1] <= 20.5) {
                                var73 = [0.6407766990291263, 0.3592233009708738];
                            } else {
                                var73 = [0.9126984126984127, 0.0873015873015873];
                            }
                        } else {
                            var73 = [1.0, 0.0];
                        }
                    } else {
                        if (input[1] <= 23.5) {
                            var73 = [0.0, 1.0];
                        } else {
                            if (input[7] <= 0.5) {
                                var73 = [0.06521739130434782, 0.9347826086956522];
                            } else {
                                var73 = [1.0, 0.0];
                            }
                        }
                    }
                }
            } else {
                if (input[13] <= 3.381500005722046) {
                    if (input[11] <= 0.5) {
                        if (input[0] <= 43.5) {
                            var73 = [1.0, 0.0];
                        } else {
                            var73 = [0.0, 1.0];
                        }
                    } else {
                        var73 = [0.0, 1.0];
                    }
                } else {
                    if (input[2] <= 1.5) {
                        if (input[7] <= 0.5) {
                            var73 = [0.5, 0.5];
                        } else {
                            var73 = [1.0, 0.0];
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            var73 = [0.0, 1.0];
                        } else {
                            var73 = [1.0, 0.0];
                        }
                    }
                }
            }
        } else {
            if (input[0] <= 48.5) {
                if (input[6] <= 0.5) {
                    if (input[1] <= 13.5) {
                        var73 = [0.5, 0.5];
                    } else {
                        var73 = [0.0, 1.0];
                    }
                } else {
                    var73 = [0.5, 0.5];
                }
            } else {
                var73 = [0.0, 1.0];
            }
        }
    } else {
        if (input[9] <= 0.5) {
            if (input[0] <= 28.5) {
                if (input[3] <= 0.5) {
                    var73 = [1.0, 0.0];
                } else {
                    var73 = [0.0, 1.0];
                }
            } else {
                if (input[6] <= 1.0) {
                    var73 = [0.0, 1.0];
                } else {
                    if (input[1] <= 23.5) {
                        if (input[6] <= 2.5) {
                            if (input[0] <= 68.5) {
                                var73 = [1.0, 0.0];
                            } else {
                                var73 = [0.0, 1.0];
                            }
                        } else {
                            if (input[0] <= 57.5) {
                                var73 = [0.0, 1.0];
                            } else {
                                var73 = [0.5, 0.5];
                            }
                        }
                    } else {
                        if (input[6] <= 4.5) {
                            if (input[13] <= 3.7225000858306885) {
                                var73 = [0.4444444444444444, 0.5555555555555556];
                            } else {
                                var73 = [0.021505376344086023, 0.978494623655914];
                            }
                        } else {
                            var73 = [0.0, 1.0];
                        }
                    }
                }
            }
        } else {
            if (input[6] <= 1.0) {
                var73 = [0.0, 1.0];
            } else {
                if (input[2] <= 3.5) {
                    if (input[7] <= 0.5) {
                        if (input[1] <= 22.0) {
                            var73 = [1.0, 0.0];
                        } else {
                            var73 = [0.0, 1.0];
                        }
                    } else {
                        var73 = [1.0, 0.0];
                    }
                } else {
                    var73 = [0.0, 1.0];
                }
            }
        }
    }
    var var74;
    if (input[3] <= 0.5) {
        if (input[0] <= 56.5) {
            if (input[7] <= 0.5) {
                if (input[9] <= 0.5) {
                    if (input[12] <= 0.5) {
                        if (input[0] <= 36.5) {
                            if (input[5] <= 1.5) {
                                var74 = [0.9209302325581395, 0.07906976744186046];
                            } else {
                                var74 = [0.0, 1.0];
                            }
                        } else {
                            if (input[1] <= 15.5) {
                                var74 = [0.6, 0.4];
                            } else {
                                var74 = [0.11578947368421053, 0.8842105263157894];
                            }
                        }
                    } else {
                        if (input[6] <= 0.5) {
                            if (input[11] <= 0.5) {
                                var74 = [0.0, 1.0];
                            } else {
                                var74 = [1.0, 0.0];
                            }
                        } else {
                            if (input[11] <= 0.5) {
                                var74 = [0.0, 1.0];
                            } else {
                                var74 = [0.9230769230769231, 0.07692307692307693];
                            }
                        }
                    }
                } else {
                    if (input[9] <= 1.5) {
                        if (input[6] <= 0.5) {
                            if (input[5] <= 0.5) {
                                var74 = [0.19230769230769232, 0.8076923076923077];
                            } else {
                                var74 = [0.0, 1.0];
                            }
                        } else {
                            var74 = [1.0, 0.0];
                        }
                    } else {
                        if (input[6] <= 0.5) {
                            if (input[13] <= 2.896499991416931) {
                                var74 = [0.8333333333333334, 0.16666666666666666];
                            } else {
                                var74 = [0.5, 0.5];
                            }
                        } else {
                            var74 = [1.0, 0.0];
                        }
                    }
                }
            } else {
                var74 = [1.0, 0.0];
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[13] <= 3.4255000352859497) {
                    var74 = [0.0, 1.0];
                } else {
                    if (input[13] <= 3.430999994277954) {
                        var74 = [0.8, 0.2];
                    } else {
                        if (input[13] <= 3.7450000047683716) {
                            if (input[1] <= 23.5) {
                                var74 = [0.002967359050445104, 0.9970326409495549];
                            } else {
                                var74 = [0.06521739130434782, 0.9347826086956522];
                            }
                        } else {
                            var74 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var74 = [1.0, 0.0];
            }
        }
    } else {
        var74 = [0.0, 1.0];
    }
    var var75;
    if (input[3] <= 0.5) {
        if (input[1] <= 19.5) {
            if (input[9] <= 2.5) {
                if (input[11] <= 1.5) {
                    if (input[12] <= 2.5) {
                        if (input[0] <= 57.5) {
                            if (input[0] <= 47.5) {
                                var75 = [0.9791970802919708, 0.020802919708029197];
                            } else {
                                var75 = [0.7402597402597403, 0.2597402597402597];
                            }
                        } else {
                            var75 = [0.0, 1.0];
                        }
                    } else {
                        var75 = [0.0, 1.0];
                    }
                } else {
                    var75 = [0.0, 1.0];
                }
            } else {
                var75 = [0.0, 1.0];
            }
        } else {
            if (input[1] <= 29.5) {
                if (input[1] <= 20.5) {
                    if (input[9] <= 0.5) {
                        if (input[13] <= 3.603000044822693) {
                            if (input[6] <= 0.5) {
                                var75 = [1.0, 0.0];
                            } else {
                                var75 = [0.3695652173913043, 0.6304347826086957];
                            }
                        } else {
                            if (input[7] <= 0.5) {
                                var75 = [0.09090909090909091, 0.9090909090909091];
                            } else {
                                var75 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[2] <= 1.5) {
                            var75 = [0.75, 0.25];
                        } else {
                            if (input[11] <= 0.5) {
                                var75 = [0.031791907514450865, 0.9682080924855492];
                            } else {
                                var75 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[1] <= 23.5) {
                        if (input[1] <= 22.5) {
                            if (input[12] <= 2.5) {
                                var75 = [0.8897058823529411, 0.11029411764705882];
                            } else {
                                var75 = [0.0, 1.0];
                            }
                        } else {
                            if (input[5] <= 0.5) {
                                var75 = [0.6862745098039216, 0.3137254901960784];
                            } else {
                                var75 = [1.0, 0.0];
                            }
                        }
                    } else {
                        if (input[13] <= 2.91949999332428) {
                            var75 = [0.0, 1.0];
                        } else {
                            if (input[7] <= 0.5) {
                                var75 = [0.08196721311475409, 0.9180327868852459];
                            } else {
                                var75 = [1.0, 0.0];
                            }
                        }
                    }
                }
            } else {
                if (input[2] <= 1.5) {
                    var75 = [0.0, 1.0];
                } else {
                    if (input[6] <= 1.5) {
                        if (input[12] <= 0.5) {
                            if (input[0] <= 55.0) {
                                var75 = [1.0, 0.0];
                            } else {
                                var75 = [0.0, 1.0];
                            }
                        } else {
                            var75 = [0.0, 1.0];
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            var75 = [0.0, 1.0];
                        } else {
                            var75 = [1.0, 0.0];
                        }
                    }
                }
            }
        }
    } else {
        var75 = [0.0, 1.0];
    }
    var var76;
    if (input[7] <= 0.5) {
        if (input[3] <= 0.5) {
            if (input[9] <= 0.5) {
                if (input[0] <= 35.5) {
                    if (input[13] <= 2.916000008583069) {
                        var76 = [1.0, 0.0];
                    } else {
                        if (input[1] <= 14.5) {
                            if (input[0] <= 23.5) {
                                var76 = [1.0, 0.0];
                            } else {
                                var76 = [0.6590909090909091, 0.3409090909090909];
                            }
                        } else {
                            if (input[6] <= 1.5) {
                                var76 = [0.9726027397260274, 0.0273972602739726];
                            } else {
                                var76 = [0.8, 0.2];
                            }
                        }
                    }
                } else {
                    if (input[0] <= 59.0) {
                        if (input[1] <= 19.5) {
                            if (input[6] <= 0.5) {
                                var76 = [0.22666666666666666, 0.7733333333333333];
                            } else {
                                var76 = [0.7272727272727273, 0.2727272727272727];
                            }
                        } else {
                            if (input[6] <= 2.5) {
                                var76 = [0.1797752808988764, 0.8202247191011236];
                            } else {
                                var76 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var76 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[13] <= 3.381500005722046) {
                    if (input[1] <= 19.5) {
                        if (input[6] <= 0.5) {
                            if (input[5] <= 0.5) {
                                var76 = [0.2, 0.8];
                            } else {
                                var76 = [0.0, 1.0];
                            }
                        } else {
                            var76 = [1.0, 0.0];
                        }
                    } else {
                        var76 = [0.0, 1.0];
                    }
                } else {
                    if (input[1] <= 16.5) {
                        var76 = [0.5, 0.5];
                    } else {
                        if (input[12] <= 0.5) {
                            if (input[0] <= 38.5) {
                                var76 = [0.6, 0.4];
                            } else {
                                var76 = [0.0, 1.0];
                            }
                        } else {
                            var76 = [0.0, 1.0];
                        }
                    }
                }
            }
        } else {
            var76 = [0.0, 1.0];
        }
    } else {
        var76 = [1.0, 0.0];
    }
    var var77;
    if (input[7] <= 0.5) {
        if (input[2] <= 2.5) {
            if (input[0] <= 36.5) {
                if (input[9] <= 1.5) {
                    if (input[13] <= 2.7410000562667847) {
                        var77 = [1.0, 0.0];
                    } else {
                        if (input[12] <= 0.5) {
                            if (input[13] <= 2.9394999742507935) {
                                var77 = [0.5357142857142857, 0.4642857142857143];
                            } else {
                                var77 = [0.896551724137931, 0.10344827586206896];
                            }
                        } else {
                            var77 = [0.0, 1.0];
                        }
                    }
                } else {
                    var77 = [1.0, 0.0];
                }
            } else {
                if (input[1] <= 19.5) {
                    if (input[10] <= 0.5) {
                        if (input[6] <= 0.5) {
                            if (input[9] <= 0.5) {
                                var77 = [0.14285714285714285, 0.8571428571428571];
                            } else {
                                var77 = [0.027777777777777776, 0.9722222222222222];
                            }
                        } else {
                            if (input[0] <= 60.5) {
                                var77 = [0.7096774193548387, 0.2903225806451613];
                            } else {
                                var77 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var77 = [0.0, 1.0];
                    }
                } else {
                    if (input[5] <= 0.5) {
                        if (input[9] <= 0.5) {
                            if (input[11] <= 0.5) {
                                var77 = [0.019736842105263157, 0.9802631578947368];
                            } else {
                                var77 = [0.058823529411764705, 0.9411764705882353];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var77 = [0.00819672131147541, 0.9918032786885246];
                            } else {
                                var77 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[0] <= 39.0) {
                            var77 = [0.375, 0.625];
                        } else {
                            if (input[5] <= 1.5) {
                                var77 = [0.02702702702702703, 0.972972972972973];
                            } else {
                                var77 = [0.0, 1.0];
                            }
                        }
                    }
                }
            }
        } else {
            if (input[9] <= 0.5) {
                if (input[1] <= 15.5) {
                    if (input[3] <= 0.5) {
                        var77 = [1.0, 0.0];
                    } else {
                        var77 = [0.0, 1.0];
                    }
                } else {
                    if (input[0] <= 44.5) {
                        var77 = [0.5, 0.5];
                    } else {
                        var77 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[1] <= 17.0) {
                    if (input[13] <= 3.1549999713897705) {
                        var77 = [0.0, 1.0];
                    } else {
                        var77 = [0.75, 0.25];
                    }
                } else {
                    if (input[1] <= 22.5) {
                        var77 = [1.0, 0.0];
                    } else {
                        var77 = [0.0, 1.0];
                    }
                }
            }
        }
    } else {
        var77 = [1.0, 0.0];
    }
    var var78;
    if (input[3] <= 0.5) {
        if (input[7] <= 0.5) {
            if (input[9] <= 0.5) {
                if (input[11] <= 0.5) {
                    var78 = [0.35778175313059035, 0.6422182468694096];
                } else {
                    if (input[6] <= 1.5) {
                        if (input[1] <= 24.5) {
                            if (input[11] <= 1.5) {
                                var78 = [0.574468085106383, 0.425531914893617];
                            } else {
                                var78 = [0.0, 1.0];
                            }
                        } else {
                            var78 = [0.0, 1.0];
                        }
                    } else {
                        var78 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[6] <= 0.5) {
                    if (input[0] <= 30.5) {
                        var78 = [1.0, 0.0];
                    } else {
                        if (input[12] <= 0.5) {
                            if (input[1] <= 17.5) {
                                var78 = [0.0, 1.0];
                            } else {
                                var78 = [0.3, 0.7];
                            }
                        } else {
                            var78 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[2] <= 2.5) {
                        if (input[12] <= 0.5) {
                            if (input[1] <= 18.0) {
                                var78 = [1.0, 0.0];
                            } else {
                                var78 = [0.003278688524590164, 0.9967213114754099];
                            }
                        } else {
                            var78 = [0.0, 1.0];
                        }
                    } else {
                        if (input[13] <= 3.6644999980926514) {
                            var78 = [0.3333333333333333, 0.6666666666666666];
                        } else {
                            var78 = [0.0, 1.0];
                        }
                    }
                }
            }
        } else {
            var78 = [1.0, 0.0];
        }
    } else {
        var78 = [0.0, 1.0];
    }
    var var79;
    if (input[1] <= 11.5) {
        if (input[9] <= 2.5) {
            if (input[3] <= 0.5) {
                if (input[0] <= 50.5) {
                    if (input[13] <= 3.0134999752044678) {
                        if (input[7] <= 0.5) {
                            if (input[11] <= 0.5) {
                                var79 = [0.8333333333333334, 0.16666666666666666];
                            } else {
                                var79 = [1.0, 0.0];
                            }
                        } else {
                            var79 = [1.0, 0.0];
                        }
                    } else {
                        var79 = [1.0, 0.0];
                    }
                } else {
                    var79 = [0.0, 1.0];
                }
            } else {
                var79 = [0.0, 1.0];
            }
        } else {
            var79 = [0.0, 1.0];
        }
    } else {
        if (input[7] <= 0.5) {
            if (input[2] <= 2.5) {
                if (input[13] <= 3.6829999685287476) {
                    if (input[1] <= 19.5) {
                        if (input[0] <= 54.5) {
                            if (input[2] <= 1.5) {
                                var79 = [0.5233644859813084, 0.4766355140186916];
                            } else {
                                var79 = [0.8904109589041096, 0.1095890410958904];
                            }
                        } else {
                            var79 = [0.0, 1.0];
                        }
                    } else {
                        if (input[10] <= 0.5) {
                            if (input[6] <= 0.5) {
                                var79 = [0.5384615384615384, 0.46153846153846156];
                            } else {
                                var79 = [0.05263157894736842, 0.9473684210526315];
                            }
                        } else {
                            var79 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[2] <= 1.5) {
                        if (input[5] <= 1.5) {
                            if (input[0] <= 39.5) {
                                var79 = [1.0, 0.0];
                            } else {
                                var79 = [0.0, 1.0];
                            }
                        } else {
                            var79 = [0.0, 1.0];
                        }
                    } else {
                        if (input[13] <= 3.7350000143051147) {
                            var79 = [0.0, 1.0];
                        } else {
                            if (input[0] <= 33.5) {
                                var79 = [1.0, 0.0];
                            } else {
                                var79 = [0.05217391304347826, 0.9478260869565217];
                            }
                        }
                    }
                }
            } else {
                if (input[12] <= 0.5) {
                    if (input[9] <= 0.5) {
                        if (input[13] <= 3.1894999742507935) {
                            var79 = [0.0015094339622641509, 0.9984905660377359];
                        } else {
                            if (input[2] <= 3.5) {
                                var79 = [0.15151515151515152, 0.8484848484848485];
                            } else {
                                var79 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[3] <= 0.5) {
                            if (input[6] <= 2.5) {
                                var79 = [0.5714285714285714, 0.42857142857142855];
                            } else {
                                var79 = [0.0, 1.0];
                            }
                        } else {
                            var79 = [0.0, 1.0];
                        }
                    }
                } else {
                    var79 = [0.0, 1.0];
                }
            }
        } else {
            var79 = [1.0, 0.0];
        }
    }
    var var80;
    if (input[1] <= 11.5) {
        if (input[12] <= 2.5) {
            if (input[0] <= 50.0) {
                if (input[2] <= 2.5) {
                    if (input[12] <= 1.0) {
                        if (input[1] <= 8.5) {
                            var80 = [1.0, 0.0];
                        } else {
                            if (input[13] <= 2.643999934196472) {
                                var80 = [0.90625, 0.09375];
                            } else {
                                var80 = [0.9951768488745981, 0.00482315112540193];
                            }
                        }
                    } else {
                        if (input[11] <= 0.5) {
                            var80 = [0.0, 1.0];
                        } else {
                            var80 = [1.0, 0.0];
                        }
                    }
                } else {
                    var80 = [0.0, 1.0];
                }
            } else {
                var80 = [0.0, 1.0];
            }
        } else {
            var80 = [0.0, 1.0];
        }
    } else {
        if (input[13] <= 3.009500026702881) {
            if (input[0] <= 28.5) {
                if (input[0] <= 25.5) {
                    var80 = [1.0, 0.0];
                } else {
                    if (input[7] <= 0.5) {
                        var80 = [0.0, 1.0];
                    } else {
                        var80 = [1.0, 0.0];
                    }
                }
            } else {
                if (input[6] <= 0.5) {
                    if (input[1] <= 12.5) {
                        if (input[3] <= 0.5) {
                            if (input[13] <= 2.8865000009536743) {
                                var80 = [0.875, 0.125];
                            } else {
                                var80 = [0.25, 0.75];
                            }
                        } else {
                            var80 = [0.0, 1.0];
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            var80 = [0.0, 1.0];
                        } else {
                            var80 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[1] <= 17.5) {
                        var80 = [1.0, 0.0];
                    } else {
                        var80 = [0.5, 0.5];
                    }
                }
            }
        } else {
            if (input[1] <= 19.5) {
                if (input[7] <= 0.5) {
                    if (input[2] <= 2.5) {
                        if (input[0] <= 42.5) {
                            if (input[0] <= 34.5) {
                                var80 = [0.972972972972973, 0.02702702702702703];
                            } else {
                                var80 = [0.6176470588235294, 0.38235294117647056];
                            }
                        } else {
                            if (input[4] <= 0.5) {
                                var80 = [0.1782178217821782, 0.8217821782178217];
                            } else {
                                var80 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[6] <= 1.0) {
                            var80 = [0.0, 1.0];
                        } else {
                            if (input[1] <= 16.5) {
                                var80 = [1.0, 0.0];
                            } else {
                                var80 = [0.5, 0.5];
                            }
                        }
                    }
                } else {
                    var80 = [1.0, 0.0];
                }
            } else {
                if (input[12] <= 0.5) {
                    if (input[7] <= 0.5) {
                        if (input[8] <= 0.5) {
                            if (input[4] <= 0.5) {
                                var80 = [0.05805243445692884, 0.9419475655430711];
                            } else {
                                var80 = [0.0, 1.0];
                            }
                        } else {
                            var80 = [0.0, 1.0];
                        }
                    } else {
                        var80 = [1.0, 0.0];
                    }
                } else {
                    if (input[11] <= 0.5) {
                        var80 = [0.0, 1.0];
                    } else {
                        if (input[2] <= 2.5) {
                            if (input[5] <= 2.5) {
                                var80 = [0.3125, 0.6875];
                            } else {
                                var80 = [0.0, 1.0];
                            }
                        } else {
                            if (input[5] <= 0.5) {
                                var80 = [0.027777777777777776, 0.9722222222222222];
                            } else {
                                var80 = [0.3333333333333333, 0.6666666666666666];
                            }
                        }
                    }
                }
            }
        }
    }
    var var81;
    if (input[3] <= 0.5) {
        if (input[10] <= 0.5) {
            if (input[6] <= 0.5) {
                if (input[0] <= 60.5) {
                    if (input[7] <= 0.5) {
                        if (input[0] <= 33.5) {
                            if (input[13] <= 2.6339999437332153) {
                                var81 = [1.0, 0.0];
                            } else {
                                var81 = [0.855072463768116, 0.14492753623188406];
                            }
                        } else {
                            if (input[12] <= 1.5) {
                                var81 = [0.2112676056338028, 0.7887323943661971];
                            } else {
                                var81 = [0.6, 0.4];
                            }
                        }
                    } else {
                        var81 = [1.0, 0.0];
                    }
                } else {
                    var81 = [0.0, 1.0];
                }
            } else {
                if (input[0] <= 60.5) {
                    if (input[1] <= 19.5) {
                        if (input[7] <= 0.5) {
                            if (input[9] <= 0.5) {
                                var81 = [0.8952380952380953, 0.10476190476190476];
                            } else {
                                var81 = [1.0, 0.0];
                            }
                        } else {
                            var81 = [1.0, 0.0];
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            if (input[9] <= 0.5) {
                                var81 = [0.2616822429906542, 0.7383177570093458];
                            } else {
                                var81 = [0.375, 0.625];
                            }
                        } else {
                            var81 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[1] <= 23.5) {
                        var81 = [0.0, 1.0];
                    } else {
                        if (input[5] <= 0.5) {
                            if (input[0] <= 64.5) {
                                var81 = [0.6666666666666666, 0.3333333333333333];
                            } else {
                                var81 = [0.0, 1.0];
                            }
                        } else {
                            if (input[13] <= 3.7619999647140503) {
                                var81 = [0.375, 0.625];
                            } else {
                                var81 = [0.030303030303030304, 0.9696969696969697];
                            }
                        }
                    }
                }
            }
        } else {
            var81 = [0.0, 1.0];
        }
    } else {
        var81 = [0.0, 1.0];
    }
    var var82;
    if (input[2] <= 2.5) {
        if (input[13] <= 3.6829999685287476) {
            if (input[1] <= 19.5) {
                if (input[5] <= 1.5) {
                    if (input[12] <= 2.5) {
                        if (input[10] <= 0.5) {
                            if (input[12] <= 0.5) {
                                var82 = [0.9735152487961477, 0.026484751203852328];
                            } else {
                                var82 = [0.8165467625899281, 0.18345323741007194];
                            }
                        } else {
                            var82 = [0.0, 1.0];
                        }
                    } else {
                        var82 = [0.0, 1.0];
                    }
                } else {
                    if (input[13] <= 3.3515000343322754) {
                        var82 = [0.0, 1.0];
                    } else {
                        var82 = [1.0, 0.0];
                    }
                }
            } else {
                if (input[7] <= 0.5) {
                    if (input[1] <= 24.5) {
                        if (input[0] <= 38.5) {
                            if (input[6] <= 0.5) {
                                var82 = [0.75, 0.25];
                            } else {
                                var82 = [1.0, 0.0];
                            }
                        } else {
                            if (input[12] <= 1.5) {
                                var82 = [0.00641025641025641, 0.9935897435897436];
                            } else {
                                var82 = [0.07692307692307693, 0.9230769230769231];
                            }
                        }
                    } else {
                        var82 = [0.0, 1.0];
                    }
                } else {
                    var82 = [1.0, 0.0];
                }
            }
        } else {
            if (input[13] <= 3.6864999532699585) {
                if (input[9] <= 0.5) {
                    if (input[0] <= 36.5) {
                        var82 = [1.0, 0.0];
                    } else {
                        if (input[2] <= 1.5) {
                            var82 = [1.0, 0.0];
                        } else {
                            var82 = [0.23076923076923078, 0.7692307692307693];
                        }
                    }
                } else {
                    var82 = [0.0, 1.0];
                }
            } else {
                if (input[11] <= 0.5) {
                    if (input[1] <= 22.5) {
                        if (input[0] <= 63.5) {
                            if (input[7] <= 0.5) {
                                var82 = [0.625, 0.375];
                            } else {
                                var82 = [1.0, 0.0];
                            }
                        } else {
                            var82 = [0.0, 1.0];
                        }
                    } else {
                        if (input[1] <= 31.5) {
                            if (input[2] <= 1.5) {
                                var82 = [1.0, 0.0];
                            } else {
                                var82 = [0.5, 0.5];
                            }
                        } else {
                            if (input[0] <= 57.5) {
                                var82 = [0.5, 0.5];
                            } else {
                                var82 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[12] <= 2.5) {
                        if (input[0] <= 59.5) {
                            var82 = [1.0, 0.0];
                        } else {
                            var82 = [0.0, 1.0];
                        }
                    } else {
                        var82 = [0.0, 1.0];
                    }
                }
            }
        }
    } else {
        if (input[3] <= 0.5) {
            if (input[13] <= 3.5460000038146973) {
                if (input[0] <= 53.5) {
                    var82 = [1.0, 0.0];
                } else {
                    var82 = [0.75, 0.25];
                }
            } else {
                if (input[11] <= 0.5) {
                    if (input[0] <= 40.5) {
                        var82 = [1.0, 0.0];
                    } else {
                        if (input[1] <= 23.5) {
                            if (input[12] <= 0.5) {
                                var82 = [0.5555555555555556, 0.4444444444444444];
                            } else {
                                var82 = [0.0, 1.0];
                            }
                        } else {
                            var82 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[5] <= 0.5) {
                        if (input[6] <= 3.5) {
                            var82 = [0.057692307692307696, 0.9423076923076923];
                        } else {
                            var82 = [0.0, 1.0];
                        }
                    } else {
                        var82 = [0.3333333333333333, 0.6666666666666666];
                    }
                }
            }
        } else {
            var82 = [0.0, 1.0];
        }
    }
    var var83;
    if (input[0] <= 40.5) {
        if (input[7] <= 0.5) {
            if (input[3] <= 0.5) {
                if (input[12] <= 0.5) {
                    if (input[5] <= 1.5) {
                        if (input[6] <= 0.5) {
                            if (input[9] <= 1.5) {
                                var83 = [0.7416666666666667, 0.25833333333333336];
                            } else {
                                var83 = [1.0, 0.0];
                            }
                        } else {
                            if (input[0] <= 37.5) {
                                var83 = [0.9739130434782609, 0.02608695652173913];
                            } else {
                                var83 = [0.16666666666666666, 0.8333333333333334];
                            }
                        }
                    } else {
                        if (input[5] <= 2.5) {
                            if (input[13] <= 3.6505000591278076) {
                                var83 = [0.6666666666666666, 0.3333333333333333];
                            } else {
                                var83 = [0.0, 1.0];
                            }
                        } else {
                            var83 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[11] <= 0.5) {
                        var83 = [0.0, 1.0];
                    } else {
                        var83 = [0.3333333333333333, 0.6666666666666666];
                    }
                }
            } else {
                var83 = [0.0, 1.0];
            }
        } else {
            var83 = [1.0, 0.0];
        }
    } else {
        if (input[0] <= 56.5) {
            if (input[2] <= 2.5) {
                if (input[9] <= 0.5) {
                    if (input[11] <= 0.5) {
                        if (input[10] <= 0.5) {
                            if (input[2] <= 1.5) {
                                var83 = [0.6276595744680851, 0.3723404255319149];
                            } else {
                                var83 = [0.7388059701492538, 0.26119402985074625];
                            }
                        } else {
                            var83 = [0.0, 1.0];
                        }
                    } else {
                        var83 = [1.0, 0.0];
                    }
                } else {
                    if (input[13] <= 3.4189999103546143) {
                        if (input[7] <= 0.5) {
                            var83 = [0.0, 1.0];
                        } else {
                            var83 = [1.0, 0.0];
                        }
                    } else {
                        var83 = [0.7333333333333333, 0.26666666666666666];
                    }
                }
            } else {
                if (input[13] <= 3.1959999799728394) {
                    if (input[11] <= 0.5) {
                        if (input[0] <= 41.5) {
                            if (input[1] <= 14.5) {
                                var83 = [0.0, 1.0];
                            } else {
                                var83 = [0.25, 0.75];
                            }
                        } else {
                            var83 = [0.0, 1.0];
                        }
                    } else {
                        if (input[12] <= 2.5) {
                            var83 = [0.4, 0.6];
                        } else {
                            var83 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[7] <= 0.5) {
                        var83 = [0.0, 1.0];
                    } else {
                        var83 = [1.0, 0.0];
                    }
                }
            }
        } else {
            if (input[3] <= 0.5) {
                if (input[9] <= 0.5) {
                    if (input[13] <= 3.8174999952316284) {
                        if (input[1] <= 21.5) {
                            if (input[5] <= 0.5) {
                                var83 = [0.01834862385321101, 0.981651376146789];
                            } else {
                                var83 = [0.1111111111111111, 0.8888888888888888];
                            }
                        } else {
                            if (input[2] <= 2.5) {
                                var83 = [0.3111111111111111, 0.6888888888888889];
                            } else {
                                var83 = [0.09090909090909091, 0.9090909090909091];
                            }
                        }
                    } else {
                        if (input[2] <= 2.5) {
                            if (input[1] <= 20.5) {
                                var83 = [0.5, 0.5];
                            } else {
                                var83 = [0.0, 1.0];
                            }
                        } else {
                            var83 = [0.0, 1.0];
                        }
                    }
                } else {
                    var83 = [0.0, 1.0];
                }
            } else {
                var83 = [0.0, 1.0];
            }
        }
    }
    var var84;
    if (input[2] <= 2.5) {
        if (input[0] <= 57.5) {
            if (input[12] <= 2.5) {
                if (input[0] <= 46.5) {
                    if (input[13] <= 3.777999997138977) {
                        if (input[10] <= 0.5) {
                            if (input[12] <= 0.5) {
                                var84 = [0.9808248914616498, 0.01917510853835022];
                            } else {
                                var84 = [0.9375, 0.0625];
                            }
                        } else {
                            var84 = [0.07692307692307693, 0.9230769230769231];
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            if (input[5] <= 0.5) {
                                var84 = [0.5625, 0.4375];
                            } else {
                                var84 = [0.0, 1.0];
                            }
                        } else {
                            var84 = [1.0, 0.0];
                        }
                    }
                } else {
                    if (input[7] <= 0.5) {
                        if (input[11] <= 0.5) {
                            if (input[2] <= 1.5) {
                                var84 = [0.0, 1.0];
                            } else {
                                var84 = [0.1111111111111111, 0.8888888888888888];
                            }
                        } else {
                            if (input[13] <= 3.569499969482422) {
                                var84 = [0.75, 0.25];
                            } else {
                                var84 = [1.0, 0.0];
                            }
                        }
                    } else {
                        var84 = [1.0, 0.0];
                    }
                }
            } else {
                var84 = [0.0, 1.0];
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[0] <= 58.5) {
                    var84 = [0.058823529411764705, 0.9411764705882353];
                } else {
                    if (input[1] <= 23.5) {
                        var84 = [0.0, 1.0];
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[12] <= 1.5) {
                                var84 = [0.0, 1.0];
                            } else {
                                var84 = [0.02564102564102564, 0.9743589743589743];
                            }
                        } else {
                            var84 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var84 = [1.0, 0.0];
            }
        }
    } else {
        if (input[3] <= 0.5) {
            if (input[2] <= 3.5) {
                if (input[7] <= 0.5) {
                    if (input[11] <= 0.5) {
                        if (input[0] <= 41.0) {
                            var84 = [1.0, 0.0];
                        } else {
                            var84 = [0.0, 1.0];
                        }
                    } else {
                        var84 = [0.0, 1.0];
                    }
                } else {
                    var84 = [1.0, 0.0];
                }
            } else {
                if (input[2] <= 5.5) {
                    if (input[9] <= 1.0) {
                        if (input[6] <= 3.5) {
                            if (input[5] <= 0.5) {
                                var84 = [0.8571428571428571, 0.14285714285714285];
                            } else {
                                var84 = [0.12, 0.88];
                            }
                        } else {
                            var84 = [0.5, 0.5];
                        }
                    } else {
                        var84 = [0.0, 1.0];
                    }
                } else {
                    var84 = [0.0, 1.0];
                }
            }
        } else {
            var84 = [0.0, 1.0];
        }
    }
    var var85;
    if (input[1] <= 11.5) {
        if (input[0] <= 50.0) {
            if (input[7] <= 0.5) {
                if (input[3] <= 0.5) {
                    if (input[1] <= 7.5) {
                        var85 = [1.0, 0.0];
                    } else {
                        if (input[0] <= 39.5) {
                            if (input[0] <= 33.5) {
                                var85 = [0.9508196721311475, 0.04918032786885246];
                            } else {
                                var85 = [0.6, 0.4];
                            }
                        } else {
                            if (input[13] <= 3.0850000381469727) {
                                var85 = [0.09090909090909091, 0.9090909090909091];
                            } else {
                                var85 = [0.5, 0.5];
                            }
                        }
                    }
                } else {
                    var85 = [0.0, 1.0];
                }
            } else {
                var85 = [1.0, 0.0];
            }
        } else {
            var85 = [0.0, 1.0];
        }
    } else {
        if (input[2] <= 2.5) {
            if (input[0] <= 55.5) {
                if (input[7] <= 0.5) {
                    if (input[9] <= 0.5) {
                        if (input[11] <= 0.5) {
                            if (input[1] <= 19.5) {
                                var85 = [0.7073170731707317, 0.2926829268292683];
                            } else {
                                var85 = [0.2125, 0.7875];
                            }
                        } else {
                            if (input[2] <= 1.5) {
                                var85 = [1.0, 0.0];
                            } else {
                                var85 = [0.9375, 0.0625];
                            }
                        }
                    } else {
                        if (input[6] <= 0.5) {
                            if (input[1] <= 14.5) {
                                var85 = [0.5, 0.5];
                            } else {
                                var85 = [0.037037037037037035, 0.9629629629629629];
                            }
                        } else {
                            if (input[1] <= 17.5) {
                                var85 = [1.0, 0.0];
                            } else {
                                var85 = [0.6666666666666666, 0.3333333333333333];
                            }
                        }
                    }
                } else {
                    var85 = [1.0, 0.0];
                }
            } else {
                if (input[9] <= 0.5) {
                    if (input[0] <= 65.5) {
                        if (input[7] <= 0.5) {
                            if (input[1] <= 21.5) {
                                var85 = [0.0, 1.0];
                            } else {
                                var85 = [0.46153846153846156, 0.5384615384615384];
                            }
                        } else {
                            var85 = [1.0, 0.0];
                        }
                    } else {
                        var85 = [0.0, 1.0];
                    }
                } else {
                    var85 = [0.0, 1.0];
                }
            }
        } else {
            if (input[6] <= 1.0) {
                var85 = [0.0, 1.0];
            } else {
                if (input[0] <= 41.5) {
                    if (input[2] <= 4.0) {
                        if (input[1] <= 22.5) {
                            var85 = [1.0, 0.0];
                        } else {
                            var85 = [0.75, 0.25];
                        }
                    } else {
                        var85 = [1.0, 0.0];
                    }
                } else {
                    if (input[1] <= 23.5) {
                        if (input[12] <= 2.5) {
                            if (input[7] <= 0.5) {
                                var85 = [0.0, 1.0];
                            } else {
                                var85 = [1.0, 0.0];
                            }
                        } else {
                            var85 = [0.0, 1.0];
                        }
                    } else {
                        if (input[7] <= 0.5) {
                            var85 = [0.0, 1.0];
                        } else {
                            var85 = [1.0, 0.0];
                        }
                    }
                }
            }
        }
    }
    var var86;
    if (input[12] <= 2.5) {
        if (input[13] <= 2.909000039100647) {
            if (input[7] <= 0.5) {
                if (input[0] <= 25.5) {
                    var86 = [1.0, 0.0];
                } else {
                    if (input[0] <= 35.5) {
                        if (input[3] <= 0.5) {
                            if (input[10] <= 0.5) {
                                var86 = [0.9090909090909091, 0.09090909090909091];
                            } else {
                                var86 = [0.0, 1.0];
                            }
                        } else {
                            var86 = [0.0, 1.0];
                        }
                    } else {
                        if (input[13] <= 2.8844999074935913) {
                            if (input[10] <= 0.5) {
                                var86 = [0.001488095238095238, 0.9985119047619048];
                            } else {
                                var86 = [0.0, 1.0];
                            }
                        } else {
                            if (input[0] <= 42.5) {
                                var86 = [0.5, 0.5];
                            } else {
                                var86 = [0.0, 1.0];
                            }
                        }
                    }
                }
            } else {
                var86 = [1.0, 0.0];
            }
        } else {
            if (input[0] <= 59.5) {
                if (input[7] <= 0.5) {
                    if (input[2] <= 2.5) {
                        if (input[13] <= 3.3459999561309814) {
                            if (input[0] <= 31.5) {
                                var86 = [0.9340659340659341, 0.06593406593406594];
                            } else {
                                var86 = [0.40298507462686567, 0.5970149253731343];
                            }
                        } else {
                            if (input[1] <= 19.5) {
                                var86 = [0.6179775280898876, 0.38202247191011235];
                            } else {
                                var86 = [0.26666666666666666, 0.7333333333333333];
                            }
                        }
                    } else {
                        if (input[6] <= 1.0) {
                            var86 = [0.0, 1.0];
                        } else {
                            if (input[5] <= 0.5) {
                                var86 = [0.46153846153846156, 0.5384615384615384];
                            } else {
                                var86 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    var86 = [1.0, 0.0];
                }
            } else {
                if (input[1] <= 21.5) {
                    var86 = [0.0, 1.0];
                } else {
                    if (input[7] <= 0.5) {
                        if (input[11] <= 0.5) {
                            var86 = [0.0, 1.0];
                        } else {
                            if (input[6] <= 1.5) {
                                var86 = [0.08695652173913043, 0.9130434782608695];
                            } else {
                                var86 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var86 = [1.0, 0.0];
                    }
                }
            }
        }
    } else {
        var86 = [0.0, 1.0];
    }
    var var87;
    if (input[7] <= 0.5) {
        if (input[12] <= 0.5) {
            if (input[10] <= 0.5) {
                if (input[3] <= 0.5) {
                    if (input[1] <= 19.5) {
                        if (input[6] <= 0.5) {
                            if (input[1] <= 11.5) {
                                var87 = [0.9154929577464789, 0.08450704225352113];
                            } else {
                                var87 = [0.425531914893617, 0.574468085106383];
                            }
                        } else {
                            if (input[1] <= 17.5) {
                                var87 = [0.9101123595505618, 0.0898876404494382];
                            } else {
                                var87 = [0.6470588235294118, 0.35294117647058826];
                            }
                        }
                    } else {
                        if (input[1] <= 20.5) {
                            if (input[13] <= 3.365000009536743) {
                                var87 = [0.5, 0.5];
                            } else {
                                var87 = [0.008902077151335312, 0.9910979228486647];
                            }
                        } else {
                            if (input[6] <= 1.5) {
                                var87 = [0.2978723404255319, 0.7021276595744681];
                            } else {
                                var87 = [0.034482758620689655, 0.9655172413793104];
                            }
                        }
                    }
                } else {
                    var87 = [0.0, 1.0];
                }
            } else {
                var87 = [0.0, 1.0];
            }
        } else {
            if (input[2] <= 2.5) {
                if (input[10] <= 0.5) {
                    if (input[2] <= 1.5) {
                        if (input[13] <= 2.9490000009536743) {
                            if (input[1] <= 10.0) {
                                var87 = [1.0, 0.0];
                            } else {
                                var87 = [0.0, 1.0];
                            }
                        } else {
                            if (input[5] <= 0.5) {
                                var87 = [0.07142857142857142, 0.9285714285714286];
                            } else {
                                var87 = [0.3333333333333333, 0.6666666666666666];
                            }
                        }
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[0] <= 62.5) {
                                var87 = [0.43478260869565216, 0.5652173913043478];
                            } else {
                                var87 = [0.0, 1.0];
                            }
                        } else {
                            var87 = [0.0, 1.0];
                        }
                    }
                } else {
                    var87 = [0.0, 1.0];
                }
            } else {
                var87 = [0.0, 1.0];
            }
        }
    } else {
        var87 = [1.0, 0.0];
    }
    var var88;
    if (input[2] <= 2.5) {
        if (input[7] <= 0.5) {
            if (input[13] <= 3.3830000162124634) {
                if (input[1] <= 18.5) {
                    if (input[2] <= 1.5) {
                        if (input[11] <= 0.5) {
                            if (input[0] <= 35.5) {
                                var88 = [0.8712871287128713, 0.12871287128712872];
                            } else {
                                var88 = [0.041666666666666664, 0.9583333333333334];
                            }
                        } else {
                            if (input[13] <= 2.9739999771118164) {
                                var88 = [0.8, 0.2];
                            } else {
                                var88 = [0.05555555555555555, 0.9444444444444444];
                            }
                        }
                    } else {
                        if (input[1] <= 14.5) {
                            if (input[11] <= 0.5) {
                                var88 = [0.9803921568627451, 0.0196078431372549];
                            } else {
                                var88 = [1.0, 0.0];
                            }
                        } else {
                            if (input[0] <= 36.5) {
                                var88 = [1.0, 0.0];
                            } else {
                                var88 = [0.5454545454545454, 0.45454545454545453];
                            }
                        }
                    }
                } else {
                    if (input[0] <= 50.5) {
                        if (input[10] <= 0.5) {
                            var88 = [1.0, 0.0];
                        } else {
                            var88 = [0.0, 1.0];
                        }
                    } else {
                        var88 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[1] <= 19.5) {
                    if (input[12] <= 2.5) {
                        if (input[9] <= 0.5) {
                            if (input[13] <= 3.5049999952316284) {
                                var88 = [0.38095238095238093, 0.6190476190476191];
                            } else {
                                var88 = [0.7142857142857143, 0.2857142857142857];
                            }
                        } else {
                            var88 = [0.0, 1.0];
                        }
                    } else {
                        var88 = [0.0, 1.0];
                    }
                } else {
                    if (input[1] <= 20.5) {
                        if (input[13] <= 3.5149999856948853) {
                            if (input[12] <= 0.5) {
                                var88 = [0.13636363636363635, 0.8636363636363636];
                            } else {
                                var88 = [0.0, 1.0];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var88 = [0.75, 0.25];
                            } else {
                                var88 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[10] <= 0.5) {
                            if (input[0] <= 33.5) {
                                var88 = [1.0, 0.0];
                            } else {
                                var88 = [0.09420289855072464, 0.9057971014492754];
                            }
                        } else {
                            var88 = [0.0, 1.0];
                        }
                    }
                }
            }
        } else {
            var88 = [1.0, 0.0];
        }
    } else {
        if (input[7] <= 0.5) {
            if (input[3] <= 0.5) {
                if (input[12] <= 0.5) {
                    if (input[1] <= 20.5) {
                        var88 = [1.0, 0.0];
                    } else {
                        var88 = [0.0, 1.0];
                    }
                } else {
                    var88 = [0.0, 1.0];
                }
            } else {
                var88 = [0.0, 1.0];
            }
        } else {
            var88 = [1.0, 0.0];
        }
    }
    var var89;
    if (input[0] <= 41.5) {
        if (input[2] <= 2.5) {
            if (input[12] <= 0.5) {
                if (input[7] <= 0.5) {
                    if (input[10] <= 0.5) {
                        if (input[13] <= 3.3994998931884766) {
                            if (input[9] <= 0.5) {
                                var89 = [0.9428571428571428, 0.05714285714285714];
                            } else {
                                var89 = [0.8095238095238095, 0.19047619047619047];
                            }
                        } else {
                            if (input[6] <= 0.5) {
                                var89 = [0.2916666666666667, 0.7083333333333334];
                            } else {
                                var89 = [0.6949152542372882, 0.3050847457627119];
                            }
                        }
                    } else {
                        var89 = [0.0, 1.0];
                    }
                } else {
                    var89 = [1.0, 0.0];
                }
            } else {
                if (input[1] <= 12.5) {
                    if (input[0] <= 39.5) {
                        var89 = [1.0, 0.0];
                    } else {
                        if (input[11] <= 0.5) {
                            var89 = [0.0, 1.0];
                        } else {
                            var89 = [1.0, 0.0];
                        }
                    }
                } else {
                    var89 = [0.0, 1.0];
                }
            }
        } else {
            if (input[7] <= 0.5) {
                if (input[12] <= 0.5) {
                    if (input[1] <= 16.0) {
                        if (input[3] <= 0.5) {
                            var89 = [1.0, 0.0];
                        } else {
                            var89 = [0.0, 1.0];
                        }
                    } else {
                        var89 = [1.0, 0.0];
                    }
                } else {
                    var89 = [0.0, 1.0];
                }
            } else {
                var89 = [1.0, 0.0];
            }
        }
    } else {
        if (input[7] <= 0.5) {
            if (input[11] <= 0.5) {
                if (input[1] <= 15.5) {
                    var89 = [0.0, 1.0];
                } else {
                    if (input[10] <= 0.5) {
                        if (input[4] <= 0.5) {
                            if (input[12] <= 0.5) {
                                var89 = [0.012295081967213115, 0.9877049180327869];
                            } else {
                                var89 = [0.0, 1.0];
                            }
                        } else {
                            var89 = [0.0, 1.0];
                        }
                    } else {
                        var89 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[13] <= 3.062000036239624) {
                    if (input[0] <= 50.0) {
                        var89 = [0.5, 0.5];
                    } else {
                        var89 = [0.0, 1.0];
                    }
                } else {
                    if (input[2] <= 2.5) {
                        if (input[13] <= 3.6549999713897705) {
                            if (input[5] <= 0.5) {
                                var89 = [0.32558139534883723, 0.6744186046511628];
                            } else {
                                var89 = [0.3333333333333333, 0.6666666666666666];
                            }
                        } else {
                            if (input[12] <= 2.5) {
                                var89 = [0.10526315789473684, 0.8947368421052632];
                            } else {
                                var89 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var89 = [0.0, 1.0];
                    }
                }
            }
        } else {
            var89 = [1.0, 0.0];
        }
    }
    var var90;
    if (input[11] <= 1.5) {
        if (input[2] <= 2.5) {
            if (input[7] <= 0.5) {
                if (input[1] <= 19.5) {
                    if (input[6] <= 0.5) {
                        if (input[5] <= 1.5) {
                            if (input[10] <= 0.5) {
                                var90 = [0.5668202764976958, 0.43317972350230416];
                            } else {
                                var90 = [0.0, 1.0];
                            }
                        } else {
                            var90 = [0.0, 1.0];
                        }
                    } else {
                        if (input[0] <= 102.5) {
                            if (input[10] <= 0.5) {
                                var90 = [0.9150943396226415, 0.08490566037735849];
                            } else {
                                var90 = [0.25, 0.75];
                            }
                        } else {
                            var90 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[0] <= 38.5) {
                        if (input[5] <= 1.5) {
                            var90 = [1.0, 0.0];
                        } else {
                            if (input[6] <= 0.5) {
                                var90 = [0.5, 0.5];
                            } else {
                                var90 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[6] <= 0.5) {
                            var90 = [0.0, 1.0];
                        } else {
                            if (input[13] <= 3.33650004863739) {
                                var90 = [0.2222222222222222, 0.7777777777777778];
                            } else {
                                var90 = [0.008298755186721992, 0.991701244813278];
                            }
                        }
                    }
                }
            } else {
                var90 = [1.0, 0.0];
            }
        } else {
            if (input[12] <= 2.5) {
                if (input[6] <= 1.0) {
                    var90 = [0.0, 1.0];
                } else {
                    if (input[9] <= 1.5) {
                        if (input[7] <= 0.5) {
                            if (input[13] <= 3.5054999589920044) {
                                var90 = [1.0, 0.0];
                            } else {
                                var90 = [0.025, 0.975];
                            }
                        } else {
                            var90 = [1.0, 0.0];
                        }
                    } else {
                        if (input[12] <= 0.5) {
                            var90 = [1.0, 0.0];
                        } else {
                            var90 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                var90 = [0.0, 1.0];
            }
        }
    } else {
        var90 = [0.0, 1.0];
    }
    var var91;
    if (input[7] <= 0.5) {
        if (input[3] <= 0.5) {
            if (input[13] <= 3.3830000162124634) {
                if (input[0] <= 38.5) {
                    if (input[9] <= 1.5) {
                        if (input[6] <= 0.5) {
                            if (input[5] <= 1.5) {
                                var91 = [0.7623762376237624, 0.2376237623762376];
                            } else {
                                var91 = [0.0, 1.0];
                            }
                        } else {
                            var91 = [1.0, 0.0];
                        }
                    } else {
                        var91 = [1.0, 0.0];
                    }
                } else {
                    if (input[2] <= 1.5) {
                        if (input[11] <= 0.5) {
                            if (input[0] <= 41.5) {
                                var91 = [0.08333333333333333, 0.9166666666666666];
                            } else {
                                var91 = [0.0, 1.0];
                            }
                        } else {
                            if (input[11] <= 2.0) {
                                var91 = [0.5, 0.5];
                            } else {
                                var91 = [0.0, 1.0];
                            }
                        }
                    } else {
                        var91 = [0.1794871794871795, 0.8205128205128205];
                    }
                }
            } else {
                if (input[13] <= 3.6829999685287476) {
                    if (input[0] <= 42.5) {
                        if (input[0] <= 34.5) {
                            if (input[6] <= 0.5) {
                                var91 = [0.6923076923076923, 0.3076923076923077];
                            } else {
                                var91 = [0.9666666666666667, 0.03333333333333333];
                            }
                        } else {
                            if (input[13] <= 3.5049999952316284) {
                                var91 = [0.3076923076923077, 0.6923076923076923];
                            } else {
                                var91 = [0.6666666666666666, 0.3333333333333333];
                            }
                        }
                    } else {
                        if (input[12] <= 1.5) {
                            if (input[6] <= 0.5) {
                                var91 = [0.0, 1.0];
                            } else {
                                var91 = [0.006711409395973154, 0.9932885906040269];
                            }
                        } else {
                            if (input[5] <= 0.5) {
                                var91 = [0.1388888888888889, 0.8611111111111112];
                            } else {
                                var91 = [0.0, 1.0];
                            }
                        }
                    }
                } else {
                    if (input[12] <= 0.5) {
                        if (input[6] <= 0.5) {
                            if (input[5] <= 1.5) {
                                var91 = [0.6153846153846154, 0.38461538461538464];
                            } else {
                                var91 = [0.0, 1.0];
                            }
                        } else {
                            if (input[5] <= 1.5) {
                                var91 = [0.04142011834319527, 0.9585798816568047];
                            } else {
                                var91 = [0.0, 1.0];
                            }
                        }
                    } else {
                        if (input[6] <= 1.5) {
                            if (input[0] <= 49.5) {
                                var91 = [0.25, 0.75];
                            } else {
                                var91 = [0.0, 1.0];
                            }
                        } else {
                            var91 = [0.0, 1.0];
                        }
                    }
                }
            }
        } else {
            var91 = [0.0, 1.0];
        }
    } else {
        var91 = [1.0, 0.0];
    }
    var var92;
    if (input[7] <= 0.5) {
        if (input[2] <= 2.5) {
            if (input[10] <= 0.5) {
                if (input[6] <= 0.5) {
                    if (input[1] <= 7.5) {
                        var92 = [1.0, 0.0];
                    } else {
                        if (input[12] <= 0.5) {
                            if (input[1] <= 11.5) {
                                var92 = [0.6875, 0.3125];
                            } else {
                                var92 = [0.4132231404958678, 0.5867768595041323];
                            }
                        } else {
                            if (input[0] <= 51.0) {
                                var92 = [0.4117647058823529, 0.5882352941176471];
                            } else {
                                var92 = [0.02857142857142857, 0.9714285714285714];
                            }
                        }
                    }
                } else {
                    if (input[13] <= 3.381500005722046) {
                        if (input[0] <= 61.5) {
                            if (input[13] <= 3.153499960899353) {
                                var92 = [1.0, 0.0];
                            } else {
                                var92 = [0.92, 0.08];
                            }
                        } else {
                            var92 = [0.0, 1.0];
                        }
                    } else {
                        if (input[0] <= 36.5) {
                            var92 = [0.9047619047619048, 0.09523809523809523];
                        } else {
                            if (input[0] <= 62.5) {
                                var92 = [0.23333333333333334, 0.7666666666666667];
                            } else {
                                var92 = [0.0, 1.0];
                            }
                        }
                    }
                }
            } else {
                var92 = [0.0045662100456621, 0.9954337899543378];
            }
        } else {
            if (input[12] <= 0.5) {
                if (input[3] <= 0.5) {
                    if (input[13] <= 3.5054999589920044) {
                        if (input[0] <= 38.0) {
                            var92 = [1.0, 0.0];
                        } else {
                            var92 = [0.0, 1.0];
                        }
                    } else {
                        if (input[2] <= 3.5) {
                            if (input[0] <= 40.0) {
                                var92 = [0.4, 0.6];
                            } else {
                                var92 = [0.0, 1.0];
                            }
                        } else {
                            var92 = [0.0, 1.0];
                        }
                    }
                } else {
                    var92 = [0.0, 1.0];
                }
            } else {
                var92 = [0.0, 1.0];
            }
        }
    } else {
        var92 = [1.0, 0.0];
    }
    var var93;
    if (input[2] <= 2.5) {
        if (input[7] <= 0.5) {
            if (input[9] <= 0.5) {
                if (input[6] <= 0.5) {
                    if (input[11] <= 2.0) {
                        if (input[13] <= 2.728500008583069) {
                            if (input[0] <= 27.5) {
                                var93 = [0.9583333333333334, 0.041666666666666664];
                            } else {
                                var93 = [0.25, 0.75];
                            }
                        } else {
                            if (input[0] <= 30.5) {
                                var93 = [0.8833333333333333, 0.11666666666666667];
                            } else {
                                var93 = [0.19008264462809918, 0.8099173553719008];
                            }
                        }
                    } else {
                        var93 = [0.0, 1.0];
                    }
                } else {
                    if (input[1] <= 19.5) {
                        if (input[1] <= 12.5) {
                            if (input[0] <= 107.0) {
                                var93 = [1.0, 0.0];
                            } else {
                                var93 = [0.0, 1.0];
                            }
                        } else {
                            if (input[13] <= 3.621000051498413) {
                                var93 = [0.9634146341463414, 0.036585365853658534];
                            } else {
                                var93 = [0.5833333333333334, 0.4166666666666667];
                            }
                        }
                    } else {
                        if (input[5] <= 1.5) {
                            if (input[8] <= 0.5) {
                                var93 = [0.1411764705882353, 0.8588235294117647];
                            } else {
                                var93 = [0.0, 1.0];
                            }
                        } else {
                            var93 = [0.0, 1.0];
                        }
                    }
                }
            } else {
                if (input[10] <= 0.5) {
                    if (input[6] <= 0.5) {
                        if (input[11] <= 0.5) {
                            if (input[9] <= 1.5) {
                                var93 = [0.05, 0.95];
                            } else {
                                var93 = [0.5833333333333334, 0.4166666666666667];
                            }
                        } else {
                            var93 = [0.0, 1.0];
                        }
                    } else {
                        if (input[12] <= 0.5) {
                            if (input[9] <= 1.5) {
                                var93 = [0.0392156862745098, 0.9607843137254902];
                            } else {
                                var93 = [0.019011406844106463, 0.9809885931558935];
                            }
                        } else {
                            var93 = [0.0, 1.0];
                        }
                    }
                } else {
                    var93 = [0.0, 1.0];
                }
            }
        } else {
            var93 = [1.0, 0.0];
        }
    } else {
        if (input[11] <= 1.5) {
            if (input[7] <= 0.5) {
                if (input[1] <= 16.0) {
                    if (input[6] <= 1.0) {
                        var93 = [0.0, 1.0];
                    } else {
                        var93 = [1.0, 0.0];
                    }
                } else {
                    if (input[1] <= 21.5) {
                        if (input[13] <= 3.537500023841858) {
                            var93 = [1.0, 0.0];
                        } else {
                            var93 = [0.2, 0.8];
                        }
                    } else {
                        var93 = [0.0, 1.0];
                    }
                }
            } else {
                var93 = [1.0, 0.0];
            }
        } else {
            var93 = [0.0, 1.0];
        }
    }
    var var94;
    if (input[7] <= 0.5) {
        if (input[3] <= 0.5) {
            if (input[12] <= 0.5) {
                if (input[1] <= 19.5) {
                    if (input[10] <= 0.5) {
                        if (input[6] <= 0.5) {
                            if (input[9] <= 0.5) {
                                var94 = [0.625, 0.375];
                            } else {
                                var94 = [0.3, 0.7];
                            }
                        } else {
                            if (input[13] <= 3.6829999685287476) {
                                var94 = [0.926605504587156, 0.07339449541284404];
                            } else {
                                var94 = [0.5, 0.5];
                            }
                        }
                    } else {
                        var94 = [0.0, 1.0];
                    }
                } else {
                    if (input[5] <= 1.5) {
                        if (input[0] <= 38.5) {
                            if (input[1] <= 26.5) {
                                var94 = [0.9565217391304348, 0.043478260869565216];
                            } else {
                                var94 = [0.6666666666666666, 0.3333333333333333];
                            }
                        } else {
                            var94 = [0.0, 1.0];
                        }
                    } else {
                        var94 = [0.0, 1.0];
                    }
                }
            } else {
                if (input[0] <= 54.5) {
                    if (input[12] <= 1.5) {
                        var94 = [0.0, 1.0];
                    } else {
                        if (input[9] <= 0.5) {
                            if (input[11] <= 0.5) {
                                var94 = [0.0, 1.0];
                            } else {
                                var94 = [0.9375, 0.0625];
                            }
                        } else {
                            var94 = [0.0, 1.0];
                        }
                    }
                } else {
                    if (input[6] <= 0.5) {
                        var94 = [0.0, 1.0];
                    } else {
                        if (input[2] <= 2.5) {
                            if (input[12] <= 1.5) {
                                var94 = [0.0, 1.0];
                            } else {
                                var94 = [0.012987012987012988, 0.987012987012987];
                            }
                        } else {
                            var94 = [0.0, 1.0];
                        }
                    }
                }
            }
        } else {
            var94 = [0.0, 1.0];
        }
    } else {
        var94 = [1.0, 0.0];
    }
    return mulVectorNumber(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(addVectors(var0, var1), var2), var3), var4), var5), var6), var7), var8), var9), var10), var11), var12), var13), var14), var15), var16), var17), var18), var19), var20), var21), var22), var23), var24), var25), var26), var27), var28), var29), var30), var31), var32), var33), var34), var35), var36), var37), var38), var39), var40), var41), var42), var43), var44), var45), var46), var47), var48), var49), var50), var51), var52), var53), var54), var55), var56), var57), var58), var59), var60), var61), var62), var63), var64), var65), var66), var67), var68), var69), var70), var71), var72), var73), var74), var75), var76), var77), var78), var79), var80), var81), var82), var83), var84), var85), var86), var87), var88), var89), var90), var91), var92), var93), var94), 0.010526315789473684);
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
