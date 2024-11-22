use ark_ff::PrimeField;

use crate::{
    circom_ir::types::{CircomAST, Op as CircomOp},
    mpc_ir::types::{MpcCircomAST, Node, Op, Wire, WireType},
};

pub fn translate<F: PrimeField>(ast: CircomAST<F>) -> eyre::Result<MpcCircomAST<F>> {
    let CircomAST {
        nodes: circom_nodes,
        signal_to_witness,
        num_inputs,
        num_outputs,
        num_signals,
        amount_wires,
        input_list,
        public_inputs,
    } = ast;

    let mut wires = vec![None; amount_wires];
    let mut nodes = Vec::with_capacity(circom_nodes.len());

    for node in circom_nodes {
        match node.op {
            CircomOp::LoadSubCmp(_, _) => unreachable!(),
            CircomOp::StoreSubCmp(_, _) => unreachable!(),
            CircomOp::Load => unreachable!(),
            CircomOp::Input(idx) => {
                assert!(node.input.is_empty());
                assert_eq!(node.output.len(), 1);
                let out = node.output[0];
                // all inputs are arithmetic shares, except for those in public_inputs
                wires[out] = Some(WireType::ArithmeticShare);
                for (name, start, size) in input_list.iter() {
                    if (*start..*start + *size).contains(&(idx + 1)) && public_inputs.contains(name)
                    {
                        wires[out] = Some(WireType::Public);
                    }
                }
                let node = Node::input(idx, out);
                nodes.push(node);
            }
            CircomOp::Output(idx) => {
                assert_eq!(node.input.len(), 1);
                assert_eq!(node.output.len(), 1);
                let input = node.input[0];
                let out = node.output[0];
                match wires[input].unwrap() {
                    WireType::Public => {
                        wires[out] = wires[input];
                        nodes.push(Node::output(idx, input, out));
                    }
                    WireType::ArithmeticShare => {
                        // this is a main output, therefore we open it
                        if idx < num_outputs {
                            let input = insert_open_arithmetic_node(&mut nodes, &mut wires, input);
                            wires[out] = Some(WireType::Public);
                            nodes.push(Node::output(idx, input, out));
                        } else {
                            wires[out] = wires[input];
                            nodes.push(Node::output(idx, input, out));
                        }
                    }
                    WireType::BinaryShare => {
                        // this is a main output, therefore we open it
                        if idx < num_outputs {
                            let input = insert_open_binary_node(&mut nodes, &mut wires, input);
                            wires[out] = Some(WireType::Public);
                            nodes.push(Node::output(idx, input, out));
                        } else {
                            // b2a, only arithmetic shares are allowed in the witness
                            // TODO if sub components still have outputs, this is probably not needed/wanted
                            wires[out] = Some(WireType::ArithmeticShare);
                            let input = insert_b2a_node(&mut nodes, &mut wires, input);
                            nodes.push(Node::output(idx, input, out));
                        }
                    }
                }
            }
            CircomOp::Constant(c) => {
                let out = node.output[0];
                let node = Node::constant(c, out);
                wires[out] = Some(WireType::Public);
                nodes.push(node);
            }
            CircomOp::Add => {
                assert_eq!(node.input.len(), 2);
                assert_eq!(node.output.len(), 1);
                let lhs = node.input[0];
                let rhs = node.input[1];
                let out = node.output[0];
                match (wires[lhs].unwrap(), wires[rhs].unwrap()) {
                    (WireType::Public, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::Add, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::ArithmeticShare) => {
                        insert_node(&mut nodes, &mut wires, Op::AddSecretSecret, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::AddSecretPublic, lhs, rhs, out);
                    }
                    (WireType::Public, WireType::ArithmeticShare) => {
                        // swap lhs and rhs to have secret val left
                        insert_node(&mut nodes, &mut wires, Op::AddSecretPublic, rhs, lhs, out);
                    }
                    (WireType::Public, WireType::BinaryShare) => {
                        let rhs = insert_b2a_node(&mut nodes, &mut wires, rhs);
                        // swap lhs and rhs to have secret val left
                        insert_node(&mut nodes, &mut wires, Op::AddSecretPublic, rhs, lhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::BinaryShare) => {
                        let rhs = insert_b2a_node(&mut nodes, &mut wires, rhs);
                        insert_node(&mut nodes, &mut wires, Op::AddSecretSecret, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::Public) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        insert_node(&mut nodes, &mut wires, Op::AddSecretPublic, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::ArithmeticShare) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        insert_node(&mut nodes, &mut wires, Op::AddSecretPublic, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::BinaryShare) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        let rhs = insert_b2a_node(&mut nodes, &mut wires, rhs);
                        insert_node(&mut nodes, &mut wires, Op::AddSecretSecret, lhs, rhs, out);
                    }
                }
            }
            CircomOp::Sub => {
                assert_eq!(node.input.len(), 2);
                assert_eq!(node.output.len(), 1);
                let lhs = node.input[0];
                let rhs = node.input[1];
                let out = node.output[0];
                match (wires[lhs].unwrap(), wires[rhs].unwrap()) {
                    (WireType::Public, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::Sub, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::ArithmeticShare) => {
                        insert_node(&mut nodes, &mut wires, Op::SubSecretSecret, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::SubSecretPublic, lhs, rhs, out);
                    }
                    (WireType::Public, WireType::ArithmeticShare) => {
                        insert_node(&mut nodes, &mut wires, Op::SubPublicSecret, lhs, rhs, out);
                    }
                    (WireType::Public, WireType::BinaryShare) => {
                        let rhs = insert_b2a_node(&mut nodes, &mut wires, rhs);
                        insert_node(&mut nodes, &mut wires, Op::SubPublicSecret, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::BinaryShare) => {
                        let rhs = insert_b2a_node(&mut nodes, &mut wires, rhs);
                        insert_node(&mut nodes, &mut wires, Op::SubSecretSecret, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::Public) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        insert_node(&mut nodes, &mut wires, Op::SubSecretPublic, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::ArithmeticShare) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        insert_node(&mut nodes, &mut wires, Op::SubSecretSecret, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::BinaryShare) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        let rhs = insert_b2a_node(&mut nodes, &mut wires, rhs);
                        insert_node(&mut nodes, &mut wires, Op::SubSecretSecret, lhs, rhs, out);
                    }
                }
            }
            CircomOp::Mul => {
                assert_eq!(node.input.len(), 2);
                assert_eq!(node.output.len(), 1);
                let lhs = node.input[0];
                let rhs = node.input[1];
                let out = node.output[0];
                match (wires[lhs].unwrap(), wires[rhs].unwrap()) {
                    (WireType::Public, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::Mul, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::ArithmeticShare) => {
                        insert_node(&mut nodes, &mut wires, Op::MulSecretSecret, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::MulSecretPublic, lhs, rhs, out);
                    }
                    (WireType::Public, WireType::ArithmeticShare) => {
                        // swap lhs and rhs to have secret val left
                        insert_node(&mut nodes, &mut wires, Op::MulSecretPublic, rhs, lhs, out);
                    }
                    (WireType::Public, WireType::BinaryShare) => {
                        let rhs = insert_b2a_node(&mut nodes, &mut wires, rhs);
                        // swap lhs and rhs to have secret val left
                        insert_node(&mut nodes, &mut wires, Op::MulSecretPublic, rhs, lhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::BinaryShare) => {
                        let rhs = insert_b2a_node(&mut nodes, &mut wires, rhs);
                        insert_node(&mut nodes, &mut wires, Op::MulSecretSecret, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::Public) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        insert_node(&mut nodes, &mut wires, Op::MulSecretPublic, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::ArithmeticShare) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        insert_node(&mut nodes, &mut wires, Op::MulSecretSecret, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::BinaryShare) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        let rhs = insert_b2a_node(&mut nodes, &mut wires, rhs);
                        insert_node(&mut nodes, &mut wires, Op::MulSecretSecret, lhs, rhs, out);
                    }
                }
            }
            CircomOp::Div => {
                assert_eq!(node.input.len(), 2);
                assert_eq!(node.output.len(), 1);
                let lhs = node.input[0];
                let rhs = node.input[1];
                let out = node.output[0];
                match (wires[lhs].unwrap(), wires[rhs].unwrap()) {
                    (WireType::Public, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::Div, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::ArithmeticShare) => {
                        insert_node(&mut nodes, &mut wires, Op::DivSecretSecret, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::DivSecretPublic, lhs, rhs, out);
                    }
                    (WireType::Public, WireType::ArithmeticShare) => {
                        insert_node(&mut nodes, &mut wires, Op::DivPublicSecret, lhs, rhs, out);
                    }
                    (WireType::Public, WireType::BinaryShare) => {
                        let rhs = insert_b2a_node(&mut nodes, &mut wires, rhs);
                        insert_node(&mut nodes, &mut wires, Op::DivPublicSecret, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::BinaryShare) => {
                        let rhs = insert_b2a_node(&mut nodes, &mut wires, rhs);
                        insert_node(&mut nodes, &mut wires, Op::DivSecretSecret, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::Public) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        insert_node(&mut nodes, &mut wires, Op::DivSecretPublic, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::ArithmeticShare) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        insert_node(&mut nodes, &mut wires, Op::DivSecretSecret, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::BinaryShare) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        let rhs = insert_b2a_node(&mut nodes, &mut wires, rhs);
                        insert_node(&mut nodes, &mut wires, Op::DivSecretSecret, lhs, rhs, out);
                    }
                }
            }
            CircomOp::Pow => {
                assert_eq!(node.input.len(), 2);
                assert_eq!(node.output.len(), 1);
                let lhs = node.input[0];
                let rhs = node.input[1];
                let out = node.output[0];
                match (wires[lhs].unwrap(), wires[rhs].unwrap()) {
                    (WireType::Public, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::Pow, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::PowSecretPublic, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::Public) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        insert_node(&mut nodes, &mut wires, Op::PowSecretPublic, lhs, rhs, out);
                    }
                    _ => panic!("pow with shared exponent not implemented"),
                }
            }
            CircomOp::IntDiv => {
                assert_eq!(node.input.len(), 2);
                assert_eq!(node.output.len(), 1);
                let lhs = node.input[0];
                let rhs = node.input[1];
                let out = node.output[0];
                match (wires[lhs].unwrap(), wires[rhs].unwrap()) {
                    (WireType::Public, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::IntDiv, lhs, rhs, out);
                    }
                    _ => panic!("shared int_div not implemented"),
                }
            }
            CircomOp::ShiftL => {
                assert_eq!(node.input.len(), 2);
                assert_eq!(node.output.len(), 1);
                let lhs = node.input[0];
                let rhs = node.input[1];
                let out = node.output[0];
                match (wires[lhs].unwrap(), wires[rhs].unwrap()) {
                    (WireType::Public, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::ShiftL, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::Public) => {
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::ShiftLSecretPublic,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    (WireType::BinaryShare, WireType::Public) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::ShiftLSecretPublic,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    _ => panic!("shared shift_left not implemented"),
                }
            }
            CircomOp::ShiftR => {
                assert_eq!(node.input.len(), 2);
                assert_eq!(node.output.len(), 1);
                let lhs = node.input[0];
                let rhs = node.input[1];
                let out = node.output[0];
                match (wires[lhs].unwrap(), wires[rhs].unwrap()) {
                    (WireType::Public, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::ShiftR, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::Public) => {
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::ShiftRSecretPublic,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    (WireType::BinaryShare, WireType::Public) => {
                        let lhs = insert_b2a_node(&mut nodes, &mut wires, lhs);
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::ShiftRSecretPublic,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    _ => panic!("shared shift_left not implemented"),
                }
            }
            CircomOp::BitOr => {
                assert_eq!(node.input.len(), 2);
                assert_eq!(node.output.len(), 1);
                let lhs = node.input[0];
                let rhs = node.input[1];
                let out = node.output[0];
                match (wires[lhs].unwrap(), wires[rhs].unwrap()) {
                    (WireType::Public, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::BitOr, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::ArithmeticShare) => {
                        let lhs = insert_a2b_node(&mut nodes, &mut wires, lhs);
                        let rhs = insert_a2b_node(&mut nodes, &mut wires, rhs);
                        insert_node(&mut nodes, &mut wires, Op::BitOrSecretSecret, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::Public) => {
                        let lhs = insert_a2b_node(&mut nodes, &mut wires, lhs);
                        insert_node(&mut nodes, &mut wires, Op::BitOrSecretPublic, lhs, rhs, out);
                    }
                    (WireType::Public, WireType::ArithmeticShare) => {
                        let rhs = insert_a2b_node(&mut nodes, &mut wires, rhs);
                        // swap lhs and rhs to have secret val left
                        insert_node(&mut nodes, &mut wires, Op::BitOrSecretPublic, rhs, lhs, out);
                    }
                    (WireType::Public, WireType::BinaryShare) => {
                        // swap lhs and rhs to have secret val left
                        insert_node(&mut nodes, &mut wires, Op::BitOrSecretPublic, rhs, lhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::BinaryShare) => {
                        let lhs = insert_a2b_node(&mut nodes, &mut wires, lhs);
                        insert_node(&mut nodes, &mut wires, Op::BitOrSecretSecret, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::BitOrSecretPublic, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::ArithmeticShare) => {
                        let rhs = insert_a2b_node(&mut nodes, &mut wires, rhs);
                        insert_node(&mut nodes, &mut wires, Op::BitOrSecretSecret, lhs, rhs, out);
                    }
                    (WireType::BinaryShare, WireType::BinaryShare) => {
                        insert_node(&mut nodes, &mut wires, Op::BitOrSecretSecret, lhs, rhs, out);
                    }
                }
            }
            CircomOp::BitAnd => {
                assert_eq!(node.input.len(), 2);
                assert_eq!(node.output.len(), 1);
                let lhs = node.input[0];
                let rhs = node.input[1];
                let out = node.output[0];
                match (wires[lhs].unwrap(), wires[rhs].unwrap()) {
                    (WireType::Public, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::BitAnd, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::ArithmeticShare) => {
                        let lhs = insert_a2b_node(&mut nodes, &mut wires, lhs);
                        let rhs = insert_a2b_node(&mut nodes, &mut wires, rhs);
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitAndSecretSecret,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    (WireType::ArithmeticShare, WireType::Public) => {
                        let lhs = insert_a2b_node(&mut nodes, &mut wires, lhs);
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitAndSecretPublic,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    (WireType::Public, WireType::ArithmeticShare) => {
                        let rhs = insert_a2b_node(&mut nodes, &mut wires, rhs);
                        // swap lhs and rhs to have secret val left
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitAndSecretPublic,
                            rhs,
                            lhs,
                            out,
                        );
                    }
                    (WireType::Public, WireType::BinaryShare) => {
                        // swap lhs and rhs to have secret val left
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitAndSecretPublic,
                            rhs,
                            lhs,
                            out,
                        );
                    }
                    (WireType::ArithmeticShare, WireType::BinaryShare) => {
                        let lhs = insert_a2b_node(&mut nodes, &mut wires, lhs);
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitAndSecretSecret,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    (WireType::BinaryShare, WireType::Public) => {
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitAndSecretPublic,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    (WireType::BinaryShare, WireType::ArithmeticShare) => {
                        let rhs = insert_a2b_node(&mut nodes, &mut wires, rhs);
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitAndSecretSecret,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    (WireType::BinaryShare, WireType::BinaryShare) => {
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitAndSecretSecret,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                }
            }
            CircomOp::BitXor => {
                assert_eq!(node.input.len(), 2);
                assert_eq!(node.output.len(), 1);
                let lhs = node.input[0];
                let rhs = node.input[1];
                let out = node.output[0];
                match (wires[lhs].unwrap(), wires[rhs].unwrap()) {
                    (WireType::Public, WireType::Public) => {
                        insert_node(&mut nodes, &mut wires, Op::BitXor, lhs, rhs, out);
                    }
                    (WireType::ArithmeticShare, WireType::ArithmeticShare) => {
                        let lhs = insert_a2b_node(&mut nodes, &mut wires, lhs);
                        let rhs = insert_a2b_node(&mut nodes, &mut wires, rhs);
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitXorSecretSecret,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    (WireType::ArithmeticShare, WireType::Public) => {
                        let lhs = insert_a2b_node(&mut nodes, &mut wires, lhs);
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitXorSecretPublic,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    (WireType::Public, WireType::ArithmeticShare) => {
                        let rhs = insert_a2b_node(&mut nodes, &mut wires, rhs);
                        // swap lhs and rhs to have secret val left
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitXorSecretPublic,
                            rhs,
                            lhs,
                            out,
                        );
                    }
                    (WireType::Public, WireType::BinaryShare) => {
                        // swap lhs and rhs to have secret val left
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitXorSecretPublic,
                            rhs,
                            lhs,
                            out,
                        );
                    }
                    (WireType::ArithmeticShare, WireType::BinaryShare) => {
                        let lhs = insert_a2b_node(&mut nodes, &mut wires, lhs);
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitXorSecretSecret,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    (WireType::BinaryShare, WireType::Public) => {
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitXorSecretPublic,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    (WireType::BinaryShare, WireType::ArithmeticShare) => {
                        let rhs = insert_a2b_node(&mut nodes, &mut wires, rhs);
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitXorSecretSecret,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                    (WireType::BinaryShare, WireType::BinaryShare) => {
                        insert_node(
                            &mut nodes,
                            &mut wires,
                            Op::BitXorSecretSecret,
                            lhs,
                            rhs,
                            out,
                        );
                    }
                }
            }
        }
    }

    dbg!(&wires);

    // all wires must have a type
    let wires = wires
        .into_iter()
        .collect::<Option<Vec<WireType>>>()
        .unwrap();

    // must have at least amount_wires, but more if new nodes were inserted
    assert!(wires.len() >= amount_wires);

    Ok(MpcCircomAST {
        nodes,
        signal_to_witness,
        num_inputs,
        num_outputs,
        num_signals,
        wires,
    })
}

/// Insert a new wire and get its id
fn add_wire(wires: &mut Vec<Option<WireType>>, wire_type: WireType) -> Wire {
    let wire = wires.len();
    wires.push(Some(wire_type));
    wire
}

/// Insert a A2B node with `input` and return its output `Wire`
fn insert_a2b_node<F: PrimeField>(
    nodes: &mut Vec<Node<F>>,
    wires: &mut Vec<Option<WireType>>,
    input: Wire,
) -> Wire {
    let out = add_wire(wires, WireType::BinaryShare);
    let node = Node::conversion(Op::A2B, input, out);
    nodes.push(node);
    out
}

/// Insert a B2A node with `input` and return its output `Wire`
fn insert_b2a_node<F: PrimeField>(
    nodes: &mut Vec<Node<F>>,
    wires: &mut Vec<Option<WireType>>,
    input: Wire,
) -> Wire {
    let out = add_wire(wires, WireType::ArithmeticShare);
    let node = Node::conversion(Op::B2A, input, out);
    nodes.push(node);
    out
}

fn insert_open_arithmetic_node<F: PrimeField>(
    nodes: &mut Vec<Node<F>>,
    wires: &mut Vec<Option<WireType>>,
    input: Wire,
) -> Wire {
    let out = add_wire(wires, WireType::Public);
    let node = Node::open(Op::OpenArihmetic, input, out);
    nodes.push(node);
    out
}

fn insert_open_binary_node<F: PrimeField>(
    nodes: &mut Vec<Node<F>>,
    wires: &mut Vec<Option<WireType>>,
    input: Wire,
) -> Wire {
    let out = add_wire(wires, WireType::Public);
    let node = Node::open(Op::OpenBinary, input, out);
    nodes.push(node);
    out
}

fn insert_node<F: PrimeField>(
    nodes: &mut Vec<Node<F>>,
    wires: &mut [Option<WireType>],
    op: Op<F>,
    lhs: Wire,
    rhs: Wire,
    out: Wire,
) {
    let out_type = match op {
        Op::Input(_)
        | Op::Output(_)
        | Op::Constant(_)
        | Op::A2B
        | Op::B2A
        | Op::OpenArihmetic
        | Op::OpenBinary => {
            panic!("not a bin_op node")
        }
        Op::Add
        | Op::Sub
        | Op::Div
        | Op::IntDiv
        | Op::Mul
        | Op::Pow
        | Op::ShiftL
        | Op::ShiftR
        | Op::BitOr
        | Op::BitAnd
        | Op::BitXor => WireType::Public,
        Op::AddSecretSecret
        | Op::AddSecretPublic
        | Op::SubPublicSecret
        | Op::SubSecretPublic
        | Op::SubSecretSecret
        | Op::MulSecretPublic
        | Op::MulSecretSecret
        | Op::DivPublicSecret
        | Op::DivSecretPublic
        | Op::DivSecretSecret
        | Op::PowSecretPublic
        | Op::ShiftLSecretPublic
        | Op::ShiftRSecretPublic => WireType::ArithmeticShare,
        Op::BitOrSecretPublic
        | Op::BitOrSecretSecret
        | Op::BitAndSecretPublic
        | Op::BitAndSecretSecret
        | Op::BitXorSecretPublic
        | Op::BitXorSecretSecret => WireType::BinaryShare,
    };
    wires[out] = Some(out_type);

    let node = Node::bin_op(op, lhs, rhs, out);
    nodes.push(node);
}
