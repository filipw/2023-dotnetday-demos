namespace RNG {

    open Microsoft.Quantum.Arithmetic;
    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Convert;
    open Microsoft.Quantum.Diagnostics;
    open Microsoft.Quantum.Intrinsic;
    open Microsoft.Quantum.Measurement;
    open Microsoft.Quantum.Preparation;

    @EntryPoint()
    operation Start() : Unit {
        EntangledKeyDistribution();
    }

    operation EntangledKeyDistribution() : Unit {
        mutable agreedTotal = 0;
        for i in 1..100 {
            use alice = Qubit[8];
            use bob = Qubit[8];

            PrepareEntangledState(bob, alice);

            let numberAlice = MeasureInteger(alice);
            let numberBob = MeasureInteger(bob);

            Message($"Alice result: {numberAlice}, Bob result: {numberBob}");
            if (numberAlice == numberBob) {
                set agreedTotal += 1;
            }
        }

        Message($"Measurements agreed: {agreedTotal}");
    }

    operation MeasureInteger(qubits : Qubit[]) : Int {
        let result = MultiM(qubits);
        return ResultArrayAsInt(result);
    }
}