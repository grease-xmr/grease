use std::time::Instant;
use log::*;
use zkuh_rs::noir_api::{Inputs, NoirError, VecInput};
use zkuh_rs::{noir_api, noir_api::compile, noir_api::CompileOptions, ultra_honk};

fn main() {
    let start = Instant::now();
    // Compile the circuit
    let _ = env_logger::try_init();
    let settings = CompileOptions::default();
    let compile_result = match compile("init", settings) {
        Ok(result) => result,
        Err(NoirError::Compilation { warnings, errors }) => {
            warn!("Compilation failed. {} warning(s)", warnings.len());
            let long_msg = errors.join("\n");
            error!("Errors:\n{long_msg}");
            return;
        }
        Err(e) => {
            warn!("Compilation failed with unexpected error: {e}");
            return;
        }
    };
    let compile_duration = start.elapsed();
    for warning in compile_result.warnings {
        warn!("NOIR: {warning}");
    }
    let program = compile_result.program;
    info!(
        "Compilation completed successfully in {}ms with noir {}. Output hash {}.",
        compile_duration.as_millis(),
        program.noir_version, program.hash,
    );
    info!(
        "Code comprises {} functions and {} unconstrained functions.",
        program.bytecode.functions.len(),
        program.bytecode.unconstrained_functions.len(),
    );
    // Execute the program with input to get the witness
    let lap_start = Instant::now();
    let inputs = Inputs::new()
        .try_add_field(
            "blinding",
            "677747657238420344629545892862113350287078346014746041349885223968406425960",
        )
        .expect("to add input blinding")
        .try_add_field(
            "blinding_DLEQ",
            "2144235790361468935043772530645960482335425265409759788405189265308656936802",
        )
        .expect("to add input blinding_DLEQ")
        .try_add_field(
            "enc_2",
            "1106098635239940503699041671268806550084808076753030002447195492368677905788",
        )
        .expect("to add enc_2")
        .try_add_field(
            "nonce_peer",
            "941362473562958445854872797494637933207453843173119022055401701738008284186",
        )
        .expect("to add nonce_peer")
        .try_add_field(
            "r_2",
            "1072106140184681314352975995361112083950550273446077810276345662155291208434",
        )
        .expect("to add addr_2")
        .try_add_field(
            "response_BabyJubJub",
            "854235210834499667423973962419711656071325410723767426196126191188738516312",
        )
        .expect("to add response_BabyJubJub")
        .try_add_field(
            "witness_0",
            "2568166237609188807669846780611238875106975738847244883423726835401425291323",
        )
        .expect("to add witness_0")
        .add_field("response_div_ed25519", [ 86u8, 159, 195, 153, 184, 214, 25, 77, 147, 109, 184, 144, 248, 
            206, 0, 209, 43, 78, 99, 142, 229, 221, 113, 23, 169, 53, 142, 87, 243, 100, 94, 248, ])
        .add_point(
            "T_0",
            "0x291b35800fd8393946e6dd8196fc0282b6fa9b251c350c3c6cb554fb6e105710",
            "0x1a5a7ad350d85509a5472630861e9c722a3cf254e2c9ab44f8fb378543f16d2d",
        )
        .expect("to add point T_0")
        .add_point(
            "fi_2",
            "0x2344f802b1745e6261a1aad7a0739f31e0f865ed7f5544675ce8c926708b43e9",
            "0x02872987ca20f74801ae722d68e96e57b7927f3e0bb90c5ed270f01ef2579165",
        )
        .expect("to add point fi_2")
        .add_point(
            "pubkey_KES",
            "0x0179cf6b6ae3d6ebc2bb82b052b799b788d370632c49888dd56d8137f562173a",
            "0x17301fd22acecfb6158e8bb8b42475a5fe1084deac5f64198ae3b8301840b568",
        )
        .expect("to add point pubkey_KES")
        .add("challenge_bytes", VecInput::new(vec![244u8, 26, 141, 141, 26, 33, 174, 44, 172, 62, 93, 61, 20,
            158, 129, 136, 138, 61, 77, 64, 160, 117, 160, 101, 241, 75, 208, 244, 192, 232, 130, 39]))
        .expect("to add point challenge")
        .add("response_div_BabyJubJub", VecInput::new(vec![229u8, 32, 143, 75, 113, 63, 229, 174, 161, 218,
            119, 35, 132, 100, 56, 52, 177, 120, 57, 228, 89, 99, 0, 157, 20, 88, 96, 20, 119, 23, 44, 115]))
        .expect("to add point response_div_BabyJubJub")
        .add("response_ed25519", VecInput::new(vec![
            2u8, 181, 34, 27, 16, 113, 96, 218, 91, 117, 140, 181, 65, 84, 200, 176, 122, 124, 116,
            167, 254, 232, 76, 52, 121, 234, 57, 141, 58, 13, 188, 3,
        ])).expect("to add point response_ed25519")
        .add("response_div_ed25519", VecInput::new(vec![86u8, 159, 195, 153, 184, 214, 25, 77, 147, 109, 184,
            144, 248, 206, 0, 209, 43, 78, 99, 142, 229, 221, 113, 23, 169, 53, 142, 87, 243, 100, 94, 248]))
        .expect("to add point response_div_ed25519");

    let input_map = inputs.as_input_map();
    let lap_duration = lap_start.elapsed();
    info!("Input processing complete in {}ms. Input map has {} entries. Executing program",
        lap_duration.as_millis(),
        input_map.len()
    );
    let lap_start = Instant::now();
    let execution_result = noir_api::execute(&program, inputs, false)
        .expect("to execute program");
    let lap_duration = lap_start.elapsed();
    info!("Execution success in {}ms.", lap_duration.as_millis());
    //let witness = execution_result.witness_stack.serialize()
    let witness = noir_api::bincode_serialize(&execution_result.witness_stack)
        .expect("to serialize witness");
    let bytecode = noir_api::bincode_serialize(&program.bytecode)
        .expect("to bincode serialize bytecode");
    let lap_start = Instant::now();
    let proof = ultra_honk::prove(&bytecode, &witness, &[]).expect("while initializing proof");
    let lap_duration = lap_start.elapsed();
    info!("Proving completed in {}ms.", lap_duration.as_millis());
    info!("Proof has {} public inputs and {} proof elements.",
        proof.public_inputs.len(),
        proof.proof.len(),
    );
    info!("Total proving time so far: {}ms.", start.elapsed().as_millis());
    let lap_start = Instant::now();
    let is_valid = ultra_honk::verify(proof).expect("while verifying proof");
    let lap_duration = lap_start.elapsed();
    info!("Verification completed in {}ms.", lap_duration.as_millis());
    if is_valid {
        info!("Proof is valid!");
    } else {
        info!("Proof is NOT valid!");
    }
}
