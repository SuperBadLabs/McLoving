use std::io::Cursor;

use mcloving_destination_observer::{
    MAX_FRAME_BYTES, ObserverCommand, ObserverError, parse_json_no_duplicates, read_bounded_frame,
};

#[test]
fn duplicate_members_and_unknown_commands_are_rejected() {
    let duplicate = br#"{"operation":"observe","operation":"observe","request":{}}"#;
    assert_eq!(
        parse_json_no_duplicates::<ObserverCommand>(duplicate),
        Err(ObserverError::MalformedResponse)
    );
    let unknown = br#"{"operation":"write","request":{}}"#;
    assert_eq!(
        parse_json_no_duplicates::<ObserverCommand>(unknown),
        Err(ObserverError::MalformedResponse)
    );
}

#[test]
fn frames_require_termination_and_obey_the_process_bound() {
    let mut valid = Cursor::new(b"{}\r\n".to_vec());
    assert_eq!(
        read_bounded_frame(&mut valid).unwrap(),
        Some(b"{}".to_vec())
    );

    let mut unterminated = Cursor::new(b"{}".to_vec());
    assert_eq!(
        read_bounded_frame(&mut unterminated),
        Err(ObserverError::MalformedRequest)
    );

    let mut oversized = Cursor::new(vec![b'x'; 256 * 1024 + 2]);
    assert_eq!(
        read_bounded_frame(&mut oversized),
        Err(ObserverError::OversizedRequest)
    );
    assert!(oversized.position() < oversized.get_ref().len() as u64);

    let mut exact_bound = vec![b'x'; MAX_FRAME_BYTES - 1];
    exact_bound.push(b'\n');
    let mut exact_bound = Cursor::new(exact_bound);
    assert_eq!(
        read_bounded_frame(&mut exact_bound).unwrap(),
        Some(vec![b'x'; MAX_FRAME_BYTES - 1])
    );

    let mut one_byte_over = vec![b'x'; MAX_FRAME_BYTES];
    one_byte_over.push(b'\n');
    let mut one_byte_over = Cursor::new(one_byte_over);
    assert_eq!(
        read_bounded_frame(&mut one_byte_over),
        Err(ObserverError::OversizedRequest)
    );
}
