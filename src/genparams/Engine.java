package genparams;

public abstract class Engine {
    private final ProveSecModel provable_security_model;//可证明安全级别
    private final PayloadSecLevel payload_security_level;//安全级别
    private final PredicateSecLevel predicate_security_level;//谓词安全你几倍
    private final String scheme_name;//方案名

    public enum ProveSecModel {
        RandomOracle, Standard
    }

    public enum PayloadSecLevel {
        CPA, CCA2
    }

    public enum PredicateSecLevel {
        NON_ANON, ANON,
    }

    public Engine(String schemeName, ProveSecModel proveSecModel, PayloadSecLevel payloadSecLevel, PredicateSecLevel predicateSecLevel) {
        this.scheme_name = schemeName;
        this.provable_security_model = proveSecModel;
        this.payload_security_level = payloadSecLevel;
        this.predicate_security_level = predicateSecLevel;
    }

    public String getEngineName() {
        return this.scheme_name;
    }

    public PayloadSecLevel getPayloadSecLevel() {
        return this.payload_security_level;
    }

    public ProveSecModel getProveSecModel() {
        return this.provable_security_model;
    }

    public PredicateSecLevel getPredicateSecLevel() { return this.predicate_security_level; }
}